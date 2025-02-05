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

class binder_impl : public plexus::stun_binder
{
    boost::asio::io_service& m_io;
    boost::asio::ip::udp::endpoint m_stun;
    boost::asio::ip::udp::endpoint m_bind;
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
                throw plexus::handshake_error();

            return (get<uint8_t>(0) ^ get_mask_byte(0)) & 0x01;
        }
    };

public:

    binder_impl(boost::asio::io_service& io, const boost::asio::ip::udp::endpoint& stun, const boost::asio::ip::udp::endpoint& bind, uint16_t punch)
        : m_io(io)
        , m_stun(stun)
        , m_bind(bind)
        , m_punch(punch)
    {
        _dbg_ << "stun server: " << stun;
        _dbg_ << "stun client: " << bind;
    }

    void reach_peer(boost::asio::yield_context yield, const boost::asio::ip::udp::endpoint& peer, uint64_t mask) noexcept(false) override
    {
        _dbg_ << "reaching peer...";

        auto timer = [start = boost::posix_time::microsec_clock::universal_time()]()
        {
            return boost::posix_time::microsec_clock::universal_time() - start;
        };

        int64_t deadline = plexus::utils::getenv<int64_t>("PLEXUS_HANDSHAKE_TIMEOUT", 60000);

        auto pin = plexus::network::create_udp_transport(m_io, m_bind);
        handshake out(0, mask);
        handshake in(mask);

        while (timer().total_milliseconds() < deadline)
        {
            try
            {
                pin->send_to(out, peer, yield);

                if (out.flag() == 1)
                {
                    _dbg_ << "handshake peer=" << peer;
                    return;
                }

                in.truncate(pin->receive_from(in, peer, yield));

                if (in.flag() == 1)
                {
                    out = handshake(1, mask);
                }
            }
            catch(const boost::system::system_error& ex)
            {
                if (ex.code() != boost::asio::error::operation_aborted)
                    throw;

                _trc_ << ex.what();
            }
        }

        throw plexus::timeout_error();
    }

    void await_peer(boost::asio::yield_context yield, const boost::asio::ip::udp::endpoint& peer, uint64_t mask) noexcept(false) override
    {
        _dbg_ << "punching upd hole to peer...";
        
        auto timer = [start = boost::posix_time::microsec_clock::universal_time()]()
        {
            return boost::posix_time::microsec_clock::universal_time() - start;
        };

        int64_t deadline = plexus::utils::getenv<int64_t>("PLEXUS_HANDSHAKE_TIMEOUT", 60000);

        auto pin = plexus::network::create_udp_transport(m_io, m_bind);

        boost::asio::ip::unicast::hops old;
        pin->get_option(old);
        pin->set_option(boost::asio::ip::unicast::hops(m_punch));
        pin->send_to(handshake(0, mask), peer, yield, 2000);
        pin->set_option(old);

        _dbg_ << "awaiting peer...";

        handshake out(1, mask);
        handshake in(mask);

        while (timer().total_milliseconds() < deadline)
        {
            try
            {
                in.truncate(pin->receive_from(in, peer, yield));

                if (in.flag() == 0)
                {
                    pin->send_to(out, peer, yield);
                }
                else
                {
                    _dbg_ << "handshake peer=" << peer;
                    return;
                }
            }
            catch(const boost::system::system_error& ex)
            {
                if (ex.code() != boost::asio::error::operation_aborted)
                    throw;

                _trc_ << ex.what();
            }
        }

        throw plexus::timeout_error();
    }

    network::traverse punch_hole(boost::asio::yield_context yield) noexcept(false) override
    {
        auto stun = plexus::create_stun_client(m_io, m_stun, m_bind);
        return stun->punch_hole(yield);
    }
};

}

std::shared_ptr<plexus::stun_binder> create_stun_binder(boost::asio::io_service& io, const boost::asio::ip::udp::endpoint& stun, const boost::asio::ip::udp::endpoint& bind, uint16_t punch) noexcept(true)
{
    boost::asio::ip::udp::socket socket(io, stun.protocol());
    socket.set_option(boost::asio::socket_base::reuse_address(true));
    socket.bind(bind);

    return std::make_shared<plexus::stun::binder_impl>(io, stun, socket.local_endpoint(), punch);
}

}
