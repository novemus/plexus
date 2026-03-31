/*
 * Copyright (c) 2022 Novemus Band. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 */

#include <plexus/network.h>
#include <plexus/features.h>
#include <plexus/utils.h>
#include <wormhole/logger.h>
#include <tubus/buffer.h>
#include <boost/asio/error.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>

namespace plexus { namespace stun {

class broker_impl : public plexus::sync_broker
{
    boost::asio::io_context& m_io;
    plexus::endpoint m_stun;
    plexus::endpoint m_udp;
    plexus::endpoint m_tcp;
    uint16_t m_punch;

    class handshake : public tubus::mutable_buffer
    {
        uint64_t m_mask;

        uint8_t get_mask_byte(size_t pos) const
        {
            return uint8_t(m_mask >> (pos * 8));
        }

    public:

        handshake(uint8_t flag, uint64_t mask) : mutable_buffer(8), m_mask(mask)
        {
            uint8_t sum = 0;
            for (size_t i = 0; i < 7; ++i)
            {
                uint8_t byte = utils::random<uint8_t>();

                if (i == 0)
                    byte = flag ? (byte | 0x01) : (byte & 0xfe);

                sum ^= byte;
                set<uint8_t>(i, byte ^ get_mask_byte(i));
            }

            set<uint8_t>(7, sum ^ get_mask_byte(7));
        }

        handshake(uint64_t mask) : mutable_buffer(8), m_mask(mask)
        {
        }

        uint8_t flag() const
        {
            uint8_t sum = get<uint8_t>(7) ^ get_mask_byte(7);

            for (size_t i = 0; i < 7; ++i)
                sum ^= get<uint8_t>(i) ^ get_mask_byte(i);

            if (sum != 0)
                throw plexus::context_error(__FUNCTION__, "bad message checksum");

            return (get<uint8_t>(0) ^ get_mask_byte(0)) & 0x01;
        }
    };

    void punch_tcp_hole(boost::asio::yield_context yield, const plexus::endpoint& peer) noexcept(false)
    {
        _dbg_ << "punching tcp hole...";

        auto tcp = plexus::network::create_tcp_socket(m_io, m_tcp, peer);
        tcp->set_option(boost::asio::ip::unicast::hops(m_punch));
        try
        {
            tcp->connect(yield, 10);
        }
        catch(const boost::system::system_error& ex)
        {
            if (ex.code() != boost::asio::error::operation_aborted)
                throw plexus::context_error(__FUNCTION__, ex.code());
        }
        tcp->shutdown();
    }

    void touch_peer(boost::asio::yield_context yield, const plexus::endpoint& peer, uint64_t nonce, plexus::relation role) noexcept(false)
    {
        auto timer = [start = boost::posix_time::microsec_clock::universal_time()]()
        {
            return boost::posix_time::microsec_clock::universal_time() - start;
        };

        int64_t deadline = plexus::utils::getenv<int64_t>("PLEXUS_HANDSHAKE_TIMEOUT", 60000);

        auto pin = plexus::network::create_udp_socket(m_io, m_udp);

        handshake out(0, nonce);
        handshake in(nonce);

        while (timer().total_milliseconds() < deadline)
        {
            try
            {
                pin->send_to(out, peer, yield);

                if (out.flag() == 1)
                {
                    _dbg_ << "handshake peer: " << peer;
                    return;
                }

                in.truncate(pin->receive_from(in, peer, yield));

                if (in.flag() == 1)
                {
                    out = handshake(1, nonce);
                }
            }
            catch(const boost::system::system_error& ex)
            {
                if (ex.code() != boost::asio::error::operation_aborted)
                    throw plexus::context_error(__FUNCTION__, ex.code());

                _trc_ << ex.what();
            }
        }

        throw plexus::timeout_error(__FUNCTION__);
    }

    void await_peer(boost::asio::yield_context yield, const plexus::endpoint& peer, uint64_t nonce, plexus::relation role) noexcept(false)
    {
        auto timer = [start = boost::posix_time::microsec_clock::universal_time()]()
        {
            return boost::posix_time::microsec_clock::universal_time() - start;
        };

        int64_t deadline = plexus::utils::getenv<int64_t>("PLEXUS_HANDSHAKE_TIMEOUT", 60000);

        auto pin = plexus::network::create_udp_socket(m_io, m_udp);

        boost::asio::ip::unicast::hops old;
        pin->get_option(old);
        pin->set_option(boost::asio::ip::unicast::hops(m_punch));
        pin->send_to(handshake(0, nonce), peer, yield);
        pin->set_option(old);

        handshake out(1, nonce);
        handshake in(nonce);

        while (timer().total_milliseconds() < deadline)
        {
            try
            {
                in.truncate(pin->receive_from(in, peer, yield));

                if (in.flag() == 0)
                {
                    pin->send_to(out, peer, yield);
                }

                if (in.flag() == 1 || role == relation::server)
                {
                    pin->send_to(out, peer, yield);

                    _dbg_ << "handshake peer: " << peer;
                    return;
                }
            }
            catch(const boost::system::system_error& ex)
            {
                if (ex.code() != boost::asio::error::operation_aborted)
                    throw plexus::context_error(__FUNCTION__, ex.code());

                _trc_ << ex.what();
            }
        }

        throw plexus::timeout_error(__FUNCTION__);
    }

    contract handshake_peer(boost::asio::yield_context yield, const plexus::reference& host, const plexus::reference& peer, bool accept) noexcept(false)
    {
        auto term = make_contract(m_udp, m_tcp, host, peer, accept);

        if (term.qos.proto != protocol::udp)
        {
            if (term.qos.role == relation::server && host.tcp.force.nat)
                punch_tcp_hole(yield, peer.tcp.outer);

            bool not_awaitable = host.udp.outer == endpoint{} || host.udp.force.mapping != firewall::independent || host.udp.force.variable_address
                              || peer.udp.outer == endpoint{} || peer.udp.force.mapping != firewall::independent || peer.udp.force.variable_address
                              || (host.udp.outer.address == peer.udp.outer.address && (!host.udp.force.hairpin || !peer.udp.force.hairpin));

            if (not_awaitable)
            {
                _wrn_ << "can't handshake peer without suitable udp traverse";
                return term;
            }
        }

        accept
            ? await_peer(yield, peer.udp.outer, term.secret, term.qos.role)
            : touch_peer(yield, peer.udp.outer, term.secret, term.qos.role);

        return term;
    }

public:

    broker_impl(boost::asio::io_context& io, const plexus::endpoint& stun, const plexus::endpoint& udp, const plexus::endpoint& tcp, uint16_t punch)
        : m_io(io)
        , m_stun(stun)
        , m_udp(udp)
        , m_tcp(tcp)
        , m_punch(punch)
    {
        if (m_udp.port == 0)
        {
            boost::asio::ip::udp::socket socket(io, stun.address.is_v6() ? boost::asio::ip::udp::v6() : boost::asio::ip::udp::v4());
            socket.set_option(boost::asio::socket_base::reuse_address(true));
            socket.bind(udp);

            auto ep = socket.local_endpoint();
            m_udp.address = ep.address();
            m_udp.port = ep.port();
        }

        if (m_tcp.port == 0)
        {
            boost::asio::ip::tcp::socket socket(io, stun.address.is_v6() ? boost::asio::ip::tcp::v6() : boost::asio::ip::tcp::v4());
            socket.set_option(boost::asio::socket_base::reuse_address(true));
            socket.bind(tcp);

            auto ep = socket.local_endpoint();
            m_tcp.address = ep.address();
            m_tcp.port = ep.port();
        }

        _dbg_ << "stun=" << m_stun << " bind=" << m_udp << "/" << m_tcp;
    }

    contract touch_peer(boost::asio::yield_context yield, const plexus::reference& host, const plexus::reference& peer) noexcept(false) override
    {
        return handshake_peer(yield, host, peer, false);
    }

    contract await_peer(boost::asio::yield_context yield, const plexus::reference& host, const plexus::reference& peer) noexcept(false) override
    {
        return handshake_peer(yield, host, peer, true);
    }

    traverse make_traverse(boost::asio::yield_context yield, protocol proto) noexcept(false) override
    {
        auto stun = plexus::create_stun_client(m_io, m_stun, m_udp, m_tcp);
        return stun->make_traverse(yield, proto);
    }
};

}

std::shared_ptr<plexus::sync_broker> create_sync_broker(boost::asio::io_context& io, const plexus::endpoint& stun, const plexus::endpoint& udp, const plexus::endpoint& tcp, uint16_t punch) noexcept(false)
{
    return std::make_shared<plexus::stun::broker_impl>(io, stun, udp, tcp, punch);
}

}
