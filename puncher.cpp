/*
 * Copyright (c) 2022 Novemus Band. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 */

#include <boost/asio/error.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include "network.h"
#include "features.h"
#include "utils.h"
#include "log.h"

namespace plexus { namespace puncher {

class handshake : public plexus::network::buffer
{
    uint64_t m_mask;

    uint8_t get_mask_byte(size_t pos) const
    {
        return uint8_t(m_mask >> (pos * 8));
    }

public:

    handshake(uint8_t flag, uint64_t mask) : plexus::network::buffer(68), m_mask(mask)
    {
        uint8_t sum = 0;
        for (size_t i = 0; i < 7; ++i)
        {
            uint8_t byte = utils::random<uint8_t>();

            if (i == 0)
                byte &= ~flag;

            sum ^= byte;
            set_byte(i, byte ^ get_mask_byte(i));
        }

        set_byte(7, sum ^ get_mask_byte(7));
    }

    handshake(uint64_t mask) : plexus::network::buffer(1500), m_mask(mask)
    {
    }

    uint8_t flag() const
    {
        uint8_t sum = get_byte(7) ^ get_mask_byte(7);

        for (size_t i = 0; i < 8; ++i)
            sum ^= get_byte(i) ^ get_mask_byte(i);

        if (sum != 0)
            throw plexus::handshake_error();

        return get_byte(0) ^ get_mask_byte(0) & 0x01;
    }
};

class tcp_transport : public plexus::network::transport
{
    endpoint m_bind;
    std::shared_ptr<plexus::network::transport> m_pin;

public:

    tcp_transport(const endpoint& bind) : m_bind(bind), m_pin(plexus::network::raw::create_tcp_transport(bind))
    {
    }

    void send(const endpoint& peer, std::shared_ptr<plexus::network::buffer> msg, int64_t timeout = 1600, uint8_t hops = 64) noexcept(false) override
    {
        std::shared_ptr<plexus::network::raw::tcp_packet> tcp = plexus::network::raw::tcp_packet::make_syn_packet(m_bind, peer, msg);
        m_pin->send(peer, tcp, timeout, hops);
    }

    void receive(const endpoint& peer, std::shared_ptr<plexus::network::buffer> msg, int64_t timeout = 1600) noexcept(false) override
    {
        m_pin->receive(peer, msg, timeout);

        std::shared_ptr<plexus::network::raw::ip_packet> ip = std::static_pointer_cast<plexus::network::raw::ip_packet>(msg);
        std::shared_ptr<plexus::network::raw::tcp_packet> tcp = ip->payload<plexus::network::raw::tcp_packet>();

        msg->move_head(ip->header_length() + tcp->data_offset() * 4, false);
    }
};

class udp_transport : public plexus::network::transport
{
    std::shared_ptr<plexus::network::transport> m_pin;

public:

    udp_transport(const endpoint& bind) : m_pin(plexus::network::create_udp_transport(bind))
    {
    }

    void send(const endpoint& peer, std::shared_ptr<plexus::network::buffer> msg, int64_t timeout = 1600, uint8_t hops = 64) noexcept(false) override
    {
        m_pin->send(peer, msg, timeout, hops);
    }

    void receive(const endpoint& peer, std::shared_ptr<plexus::network::buffer> msg, int64_t timeout = 1600) noexcept(false) override
    {
        m_pin->receive(peer, msg, timeout);
    }
};

template<class transport> class strategy : public plexus::nat_puncher
{
    endpoint m_stun;
    endpoint m_bind;
    uint8_t  m_hops;

public:

    strategy(const endpoint& stun, const endpoint& bind, uint8_t hops)
        : m_stun(stun)
        , m_bind(bind)
        , m_hops(hops)
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

        auto pin = std::make_shared<transport>(m_bind);
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

        auto pin = std::make_shared<transport>(m_bind);
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

                pin->send(peer, std::make_shared<handshake>(0, mask), 1600, m_hops);

                _trc_ << ex.what();
            }
        }

        throw plexus::timeout_error();
    }

    endpoint punch_hole_to_peer(const endpoint& peer) noexcept(false) override
    {
        _dbg_ << "punching hole to peer...";

        endpoint ep = obtain_endpoint();

        auto pin = std::make_shared<transport>(m_bind);
        pin->send(peer, std::make_shared<handshake>(0, 0), 1600, m_hops);

        return ep;
    }

    endpoint obtain_endpoint() noexcept(false) override
    {
        auto stun = plexus::create_stun_client(m_stun, m_bind);
        return stun->obtain_endpoint();
    }

    traverse explore_network() noexcept(false) override
    {
        auto stun = plexus::create_stun_client(m_stun, m_bind);
        return stun->explore_network();
    }
};

}

std::shared_ptr<plexus::nat_puncher> create_udp_puncher(const endpoint& stun, const endpoint& bind, uint8_t hops)
{
    return std::make_shared<plexus::puncher::strategy<plexus::puncher::udp_transport>>(stun, bind, hops);
}

std::shared_ptr<plexus::nat_puncher> create_tcp_puncher(const endpoint& stun, const endpoint& bind, uint8_t hops)
{
    return std::make_shared<plexus::puncher::strategy<plexus::puncher::tcp_transport>>(stun, bind, hops);
}

}
