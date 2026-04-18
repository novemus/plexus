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

boost::posix_time::time_duration connect_delay()
{
    static const boost::posix_time::milliseconds s_delay(plexus::utils::getenv<int64_t>("PLEXUS_CONNECT_DELAY", 1000));
    return s_delay;
}

boost::posix_time::time_duration sync_timeout()
{
    static const boost::posix_time::milliseconds s_timeout(plexus::utils::getenv<int64_t>("PLEXUS_SYNC_TIMEOUT", 20000));
    return s_timeout;
}

boost::posix_time::ptime calc_sync_time(const boost::posix_time::ptime& host, const boost::posix_time::ptime& peer, schema role)
{
    return role == schema::client
         ? std::min(std::max(host, peer), boost::posix_time::microsec_clock::universal_time()) + sync_timeout() + connect_delay()
         : std::min(std::max(host, peer), boost::posix_time::microsec_clock::universal_time()) + sync_timeout();
}

class broker_impl : public plexus::sync_broker
{
    boost::asio::io_context& m_io;
    location m_stun;
    location m_bind;
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

    void punch_tcp_hole(boost::asio::yield_context yield, const endpoint& peer) noexcept(false)
    {
        _dbg_ << "punching tcp hole...";

        auto tcp = plexus::network::create_tcp_socket(m_io, m_bind.tcp, peer);
        tcp->set_option(boost::asio::ip::unicast::hops(m_punch));
        try
        {
            tcp->connect(yield, 10);
            tcp->shutdown();
        }
        catch(const boost::system::system_error& ex)
        {
            if (ex.code() != boost::asio::error::operation_aborted)
                throw plexus::context_error(__FUNCTION__, ex.code());
        }
    }

    void touch_peer(boost::asio::yield_context yield, const endpoint& peer, uint64_t nonce, schema role) noexcept(false)
    {
        _dbg_ << "touch peer...";

        auto timer = [start = boost::posix_time::microsec_clock::universal_time()]()
        {
            return boost::posix_time::microsec_clock::universal_time() - start;
        };

        int64_t deadline = plexus::utils::getenv<int64_t>("PLEXUS_HANDSHAKE_TIMEOUT", 60000);

        auto pin = plexus::network::create_udp_socket(m_io, m_bind.udp);

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

    void await_peer(boost::asio::yield_context yield, const endpoint& peer, uint64_t nonce, schema role) noexcept(false)
    {
        _dbg_ << "await peer...";

        auto timer = [start = boost::posix_time::microsec_clock::universal_time()]()
        {
            return boost::posix_time::microsec_clock::universal_time() - start;
        };

        int64_t deadline = plexus::utils::getenv<int64_t>("PLEXUS_HANDSHAKE_TIMEOUT", 60000);

        auto pin = plexus::network::create_udp_socket(m_io, m_bind.udp);

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

                if (in.flag() == 1 || role == schema::server)
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
        auto term = make_contract(m_bind, host, peer, accept);

        if (term.qos.proto != protocol::udp)
        {
            if (term.qos.role == schema::server && host.tcp.force.nat)
                punch_tcp_hole(yield, peer.tcp.outer);

            bool no_udp = host.udp.outer.address.is_v4() != peer.udp.outer.address.is_v4()
                    || host.udp.outer.address.is_unspecified() || host.udp.force.mapping != firewall::independent || host.udp.force.variable_address
                    || peer.udp.outer.address.is_unspecified() || peer.udp.force.mapping != firewall::independent || peer.udp.force.variable_address
                    || (host.udp.outer.address == peer.udp.outer.address && (!host.udp.force.hairpin || !peer.udp.force.hairpin));

            if (no_udp)
            {
                _dbg_ << "start time-point synchronization...";

                boost::asio::deadline_timer timer(m_io);
                timer.expires_at(calc_sync_time(host.timestamp, peer.timestamp, term.qos.role));
                boost::system::error_code ec;
                timer.async_wait(yield[ec]);

                _dbg_ << "synchronization finished";
                return term;
            }
        }

        accept
            ? await_peer(yield, peer.udp.outer, term.secret, term.qos.role)
            : touch_peer(yield, peer.udp.outer, term.secret, term.qos.role);

        if (term.qos.role == schema::client)
        {
            boost::asio::deadline_timer timer(m_io);
            timer.expires_from_now(connect_delay());
            boost::system::error_code ec;
            timer.async_wait(yield[ec]);
        }

        return term;
    }

public:

    broker_impl(boost::asio::io_context& io, const location& stun, const location& bind, uint16_t punch)
        : m_io(io)
        , m_punch(punch)
    {
        m_stun.udp = stun.udp;
        m_stun.tcp = stun.tcp;
        m_bind.udp = utils::locate<boost::asio::ip::udp>(bind.udp);
        m_bind.tcp = utils::locate<boost::asio::ip::tcp>(bind.tcp);

        _dbg_ << "stun: udp=" << m_stun.udp << " tcp=" << m_stun.tcp;
        _dbg_ << "bind: udp=" << m_bind.udp << " tcp=" << m_bind.tcp;
    }

    contract touch_peer(boost::asio::yield_context yield, const plexus::reference& host, const plexus::reference& peer) noexcept(false) override
    {
        return handshake_peer(yield, host, peer, false);
    }

    contract await_peer(boost::asio::yield_context yield, const plexus::reference& host, const plexus::reference& peer) noexcept(false) override
    {
        return handshake_peer(yield, host, peer, true);
    }

    traverse make_traverse(boost::asio::yield_context yield, protocol proto, checkup mode) noexcept(false) override
    {
        auto stun = plexus::create_stun_client(m_io, m_stun, m_bind);
        return stun->make_traverse(yield, proto, mode);
    }
};

}

std::shared_ptr<plexus::sync_broker> create_sync_broker(boost::asio::io_context& io, const location& stun, const location& bind, uint16_t punch) noexcept(false)
{
    return std::make_shared<plexus::stun::broker_impl>(io, stun, bind, punch);
}

}
