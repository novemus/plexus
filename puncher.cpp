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
    endpoint m_stun;
    endpoint m_bind;

    class handshake : public plexus::network::buffer
    {
        uint64_t m_mask;

        uint8_t get_mask_byte(size_t pos) const
        {
            return uint8_t(m_mask >> (pos * 8));
        }

    public:

        handshake(uint8_t flag, uint64_t mask) : plexus::network::buffer(8, 60), m_mask(mask)
        {
            uint8_t sum = 0;
            for (size_t i = 0; i < 7; ++i)
            {
                uint8_t byte = utils::random<uint8_t>();

                if (i == 0)
                    byte = flag ? (byte | 0x01) : (byte & 0xfe);

                sum ^= byte;
                set_byte(i, byte ^ get_mask_byte(i));
            }

            set_byte(7, sum ^ get_mask_byte(7));
        }

        handshake(uint64_t mask) : plexus::network::buffer(68), m_mask(mask)
        {
        }

        uint8_t flag() const
        {
            uint8_t sum = get_byte(7) ^ get_mask_byte(7);

            for (size_t i = 0; i < 7; ++i)
                sum ^= get_byte(i) ^ get_mask_byte(i);

            if (sum != 0)
                throw plexus::handshake_error();

            return (get_byte(0) ^ get_mask_byte(0)) & 0x01;
        }
    };

public:

    puncher(const endpoint& stun, const endpoint& bind)
        : m_stun(stun)
        , m_bind(bind)
    {
    }

    void reach_peer(const endpoint& peer, uint64_t mask) noexcept(false) override
    {
        _dbg_ << "reaching peer...";

        auto timer = [start = boost::posix_time::microsec_clock::universal_time()]()
        {
            return boost::posix_time::microsec_clock::universal_time() - start;
        };

        int64_t deadline = plexus::utils::getenv<int64_t>("PLEXUS_HANDSHAKE_TIMEOUT", 60000);

        auto pin = plexus::network::create_udp_transport(m_bind);
        auto out = std::make_shared<handshake>(0, mask);
        auto in = std::make_shared<handshake>(mask);

        while (timer().total_milliseconds() < deadline)
        {
            try
            {
                pin->send(peer, out);

                if (out->flag() == 1)
                {
                    _dbg_ << "handshake peer=" << peer.first << ":" << peer.second;
                    return;
                }

                pin->receive(peer, in);

                if (in->flag() == 1)
                {
                    out = std::make_shared<handshake>(1, mask);
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

    void await_peer(const endpoint& peer, uint64_t mask) noexcept(false) override
    {
        _dbg_ << "awaiting peer...";

        auto timer = [start = boost::posix_time::microsec_clock::universal_time()]()
        {
            return boost::posix_time::microsec_clock::universal_time() - start;
        };

        int64_t deadline = plexus::utils::getenv<int64_t>("PLEXUS_HANDSHAKE_TIMEOUT", 60000);

        auto pin = plexus::network::create_udp_transport(m_bind);
        auto out = std::make_shared<handshake>(1, mask);
        auto in = std::make_shared<handshake>(mask);

        while (timer().total_milliseconds() < deadline)
        {
            try
            {
                pin->receive(peer, in);

                if (in->flag() == 0)
                {
                    pin->send(peer, out);
                }
                else
                {
                    _dbg_ << "handshake peer=" << peer.first << ":" << peer.second;
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

    endpoint punch_udp_hole_to_peer(const endpoint& peer, uint8_t hops) noexcept(false) override
    {
        _dbg_ << "punching udp hole to peer...";

        endpoint ep = reflect_endpoint();

        auto pin = plexus::network::create_udp_transport(m_bind);
        pin->send(peer, std::make_shared<handshake>(0, 0), 2000, hops);

        return ep;
    }

    void trace_tcp_syn_to_peer(const endpoint& peer, uint8_t hops, uint8_t trace) noexcept(false) override
    {
        _dbg_ << "tracing tcp syn to peer...";

        uint8_t max_hops = hops + trace;

        while (hops < max_hops)
        {
            try
            {
                auto tcp = plexus::network::create_tcp_client(peer, m_bind, 2000, hops);

                tcp->connect();
                tcp->shutdown();

                _wrn_ << "tcp trace reached the peer";

                return;
            }
            catch(const boost::system::system_error& ex)
            {
                if (ex.code() == boost::asio::error::operation_aborted)
                {
                    return;
                }
                else if (ex.code() == boost::asio::error::host_unreachable)
                {
                    ++hops;
                }
                else
                {
                    throw;
                }
            }
        }

        _wrn_ << "tcp trace did not reach unresponsive router";
    }

    endpoint reflect_endpoint() noexcept(false) override
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

std::shared_ptr<plexus::nat_puncher> create_nat_puncher(const endpoint& stun, const endpoint& bind)
{
    return std::make_shared<plexus::puncher>(stun, bind);
}

}
