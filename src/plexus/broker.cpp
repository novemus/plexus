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
#include <ricochet/agent.h>
#include <wormhole/logger.h>
#include <tubus/buffer.h>
#include <plexus/network.h>
#include <plexus/features.h>
#include <plexus/utils.h>

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

namespace rico = ricochet;

class broker_impl : public plexus::link_broker
{
    struct relays
    {
        struct session
        {
            std::shared_ptr<rico::agent> agent;
            plexus::endpoint relay;
        };

        session udp;
        session tcp;
    };

    boost::asio::io_context& m_io;
    location m_stun;
    location m_bind;
    uint16_t m_punch;
    relays   m_rico;

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

        boost::asio::ip::udp::endpoint remote = peer;
        while (timer().total_milliseconds() < deadline)
        {
            try
            {
                pin->send_to(out, remote, yield);

                if (out.flag() == 1)
                {
                    _dbg_ << "handshake peer " << peer;
                    return;
                }

                in.truncate(pin->receive_from(in, remote, yield));

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

        boost::asio::ip::udp::endpoint remote = peer;
        while (timer().total_milliseconds() < deadline)
        {
            try
            {
                in.truncate(pin->receive_from(in, remote, yield));

                if (in.flag() == 0)
                {
                    pin->send_to(out, remote, yield);
                }

                if (in.flag() == 1 || role == schema::server)
                {
                    pin->send_to(out, remote, yield);

                    _dbg_ << "handshake peer " << remote;
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

    static endpoint make_endpoint_for_relay(const reference::mapping& map)
    {
        return plexus::endpoint {
                map.force.variable_address 
                    ? map.outer.address.is_v4() ? boost::asio::ip::address(boost::asio::ip::address_v4()) : boost::asio::ip::address(boost::asio::ip::address_v6())
                    : map.outer.address,
                map.force.mapping == firewall::relation::independent 
                    ? map.outer.port 
                    : static_cast<uint16_t>(0)
            };
    }

    contract handshake_peer(boost::asio::yield_context yield, const reference& host, const reference& peer, bool accept) noexcept(false)
    {
        auto term = make_contract(m_bind, host, peer, accept);

        if (term.qos.proto != protocol::udp && (term.alien == host.tcp.relay || term.alien == peer.tcp.relay))
        {
            if (term.alien == m_rico.tcp.relay)
                run_tcp_relay(yield, make_endpoint_for_relay(host.tcp), make_endpoint_for_relay(peer.tcp), term.qos.role);
            else
                _dbg_ << "using peer's tcp relay " << peer.tcp.relay;

            return term;
        }

        if (term.qos.proto == protocol::udp && (term.alien == host.udp.relay || term.alien == peer.udp.relay))
        {
            if (term.alien == m_rico.udp.relay)
                run_udp_relay(yield, make_endpoint_for_relay(host.udp), make_endpoint_for_relay(peer.udp), term.qos.role);
            else
                _dbg_ << "using peer's udp relay " << peer.udp.relay;

            return term;
        }

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

    void run_tcp_relay(boost::asio::yield_context yield, const endpoint& host, const endpoint& peer, schema method) noexcept(false)
    {
        if (!m_rico.tcp.agent)
            throw plexus::context_error("run_tcp_relay", "no relay session");

        try
        {
            rico::peer red(host.address, host.port, method != plexus::schema::server ? rico::schema::client : rico::schema::server);
            rico::peer blue(peer.address, peer.port, method == plexus::schema::client ? rico::schema::server : rico::schema::client);

            m_rico.tcp.agent->launch_relay(yield, red, blue);

            _dbg_ << "tcp relay " << m_rico.tcp.relay << " is launched";
        }
        catch (const std::exception& ex)
        {
            throw plexus::context_error("run_tcp_relay", ex.what());
        }
    }

    void run_udp_relay(boost::asio::yield_context yield, const endpoint& host, const endpoint& peer, schema method) noexcept(false)
    {
        if (!m_rico.udp.agent)
            throw plexus::context_error("run_udp_relay", "no relay session");

        try
        {
            rico::peer red(host.address, host.port, method != plexus::schema::server ? rico::schema::client : rico::schema::server);
            rico::peer blue(peer.address, peer.port, method == plexus::schema::client ? rico::schema::server : rico::schema::client);

            m_rico.udp.agent->launch_relay(yield, red, blue);

            _dbg_ << "udp relay " << m_rico.udp.relay << " is launched";
        }
        catch (const std::exception& ex)
        {
            throw plexus::context_error("run_udp_relay", ex.what());
        }
    }

public:

    broker_impl(boost::asio::io_context& io, const location& stun, const location& bind, uint16_t punch, const ricochet& relay)
        : m_io(io)
        , m_punch(punch)
    {
        m_stun.udp = stun.udp;
        m_stun.tcp = stun.tcp;
        m_bind.udp = utils::locate<boost::asio::ip::udp>(bind.udp);
        m_bind.tcp = utils::locate<boost::asio::ip::tcp>(bind.tcp);

        _dbg_ << "stun: udp=" << m_stun.udp << " tcp=" << m_stun.tcp;
        _dbg_ << "bind: udp=" << m_bind.udp << " tcp=" << m_bind.tcp;

        if (!relay.server.address.is_unspecified() && relay.server.port != 0)
        {
            m_rico.udp.agent = rico::create_agent(relay.server, relay.cert, relay.key, relay.ca);
            m_rico.tcp.agent = rico::create_agent(relay.server, relay.cert, relay.key, relay.ca);
        }
    }

    plexus::endpoint get_tcp_relay(boost::asio::yield_context yield) noexcept(false) override
    {
        if (!m_rico.tcp.agent)
            return plexus::endpoint { m_bind.tcp.address.is_v4() ? boost::asio::ip::address(boost::asio::ip::address_v4()) : boost::asio::ip::address(boost::asio::ip::address_v6()), 0 };

        try
        {
            rico::endpoint out;
            m_rico.tcp.agent->assign_relay(yield, m_bind.tcp.address.is_v4() ? rico::protocol::tcp4 : rico::protocol::tcp6, out);
            m_rico.tcp.relay.address = out.address();
            m_rico.tcp.relay.port = out.port();
            return m_rico.tcp.relay;
        }
        catch (const std::exception& ex)
        {
            _wrn_ << "Can't acquire tcp relay: " << ex.what();
        }

        return plexus::endpoint { m_bind.tcp.address.is_v4() ? boost::asio::ip::address(boost::asio::ip::address_v4()) : boost::asio::ip::address(boost::asio::ip::address_v6()), 0 };
    }

    plexus::endpoint get_udp_relay(boost::asio::yield_context yield) noexcept(false) override
    {
        if (!m_rico.udp.agent)
            return plexus::endpoint { m_bind.udp.address.is_v4() ? boost::asio::ip::address(boost::asio::ip::address_v4()) : boost::asio::ip::address(boost::asio::ip::address_v6()), 0 };

        try
        {
            rico::endpoint out;
            m_rico.udp.agent->assign_relay(yield, m_bind.udp.address.is_v4() ? rico::protocol::udp4 : rico::protocol::udp6, out);
            m_rico.udp.relay.address = out.address();
            m_rico.udp.relay.port = out.port();
            return m_rico.udp.relay;
        }
        catch (const std::exception& ex)
        {
            _wrn_ << "Can't acquire udp relay: " << ex.what();
        }

        return plexus::endpoint { m_bind.udp.address.is_v4() ? boost::asio::ip::address(boost::asio::ip::address_v4()) : boost::asio::ip::address(boost::asio::ip::address_v6()), 0 };
    }

    contract touch_peer(boost::asio::yield_context yield, const reference& host, const reference& peer) noexcept(false) override
    {
        return handshake_peer(yield, host, peer, false);
    }

    contract await_peer(boost::asio::yield_context yield, const reference& host, const reference& peer) noexcept(false) override
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

std::shared_ptr<plexus::link_broker> create_link_broker(boost::asio::io_context& io, const location& stun, const location& bind, uint16_t punch, const ricochet& relay) noexcept(false)
{
    return std::make_shared<plexus::stun::broker_impl>(io, stun, bind, punch, relay);
}

}
