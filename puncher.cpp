/*
 * Copyright (c) 2022 Novemus Band. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 */

#include "network.h"
#include "features.h"
#include "utils.h"
#include <logger.h>
#include <boost/asio/error.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>

namespace plexus {

class puncher : public plexus::nat_puncher
{
    boost::asio::ip::udp::endpoint m_stun;
    boost::asio::ip::udp::endpoint m_bind;

    class handshake : public tubus::mutable_buffer
    {
        uint64_t m_mask;

        uint8_t get_mask_byte(size_t pos) const
        {
            return uint8_t(m_mask >> (pos * 8));
        }

    public:

        handshake(uint8_t flag, uint64_t mask) : mutable_buffer(60), m_mask(mask)
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

        handshake(uint64_t mask) : mutable_buffer(60), m_mask(mask)
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

    puncher(const boost::asio::ip::udp::endpoint& stun, const boost::asio::ip::udp::endpoint& bind)
        : m_stun(stun)
        , m_bind(bind)
    {
    }

    void reach_peer(const boost::asio::ip::udp::endpoint& peer, uint64_t mask) noexcept(false) override
    {
        _dbg_ << "reaching peer...";

        auto timer = [start = boost::posix_time::microsec_clock::universal_time()]()
        {
            return boost::posix_time::microsec_clock::universal_time() - start;
        };

        int64_t deadline = plexus::utils::getenv<int64_t>("PLEXUS_HANDSHAKE_TIMEOUT", 60000);

        auto pin = plexus::network::create_udp_transport(m_bind);
        handshake out(0, mask);
        handshake in(mask);

        while (timer().total_milliseconds() < deadline)
        {
            try
            {
                pin->send(peer, out);

                if (out.flag() == 1)
                {
                    _dbg_ << "handshake peer=" << peer;
                    return;
                }

                in.truncate(pin->receive(peer, in));

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

    void await_peer(const boost::asio::ip::udp::endpoint& peer, uint64_t mask) noexcept(false) override
    {
        _dbg_ << "awaiting peer...";

        auto timer = [start = boost::posix_time::microsec_clock::universal_time()]()
        {
            return boost::posix_time::microsec_clock::universal_time() - start;
        };

        int64_t deadline = plexus::utils::getenv<int64_t>("PLEXUS_HANDSHAKE_TIMEOUT", 60000);

        auto pin = plexus::network::create_udp_transport(m_bind);
        handshake out(1, mask);
        handshake in(mask);

        while (timer().total_milliseconds() < deadline)
        {
            try
            {
                in.truncate(pin->receive(peer, in));

                if (in.flag() == 0)
                {
                    pin->send(peer, out);
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

    boost::asio::ip::udp::endpoint punch_hole_to_peer(const boost::asio::ip::udp::endpoint& peer, uint8_t hops) noexcept(false) override
    {
        _dbg_ << "punching udp hole to peer...";

        auto ep = reflect_endpoint();

        auto pin = plexus::network::create_udp_transport(m_bind);
        pin->send(peer, handshake(0, 0), 2000, hops);

        return ep;
    }

    boost::asio::ip::udp::endpoint reflect_endpoint() noexcept(false) override
    {
        auto stun = plexus::create_stun_client(m_stun, m_bind);
        return stun->reflect_endpoint();
    }

    traverse explore_network() noexcept(false) override
    {
        auto stun = plexus::create_stun_client(m_stun, m_bind);
        return stun->explore_network();
    }
};

std::shared_ptr<plexus::nat_puncher> create_nat_puncher(const boost::asio::ip::udp::endpoint& stun, boost::asio::ip::udp::endpoint& bind)
{
    boost::asio::io_service io;
    boost::asio::ip::udp::socket socket(io, bind.protocol());

    socket.set_option(boost::asio::socket_base::reuse_address(true));
    socket.bind(bind);
    bind = socket.local_endpoint();

    return std::make_shared<plexus::puncher>(stun, bind);
}

}
