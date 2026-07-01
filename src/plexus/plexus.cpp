/*
 * Copyright (c) 2022 Novemus Band. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 */

#include "plexus.h"
#include <plexus/plexus.h>
#include <plexus/features.h>
#include <plexus/utils.h>
#include <wormhole/logger.h>
#include <bitset>

namespace plexus {

constexpr const uint16_t SSL_SERVER = 0x0001;
constexpr const uint16_t SSL_CLIENT = 0x0002;
constexpr const uint16_t SSL_MUTUAL = 0x0004;
constexpr const uint16_t TCP_SERVER = 0x0008;
constexpr const uint16_t TCP_CLIENT = 0x0010;
constexpr const uint16_t TCP_MUTUAL = 0x0020;
constexpr const uint16_t UDP_SERVER = 0x0040;
constexpr const uint16_t UDP_CLIENT = 0x0080;
constexpr const uint16_t UDP_MUTUAL = 0x0100;

std::ostream& operator<<(std::ostream& out, const firewall& val) noexcept(false)
{
    if (out.rdbuf())
    {
        uint8_t num = uint8_t(val.nat << 7)
                    | uint8_t(val.hairpin << 6)
                    | uint8_t(val.random_port << 5)
                    | uint8_t(val.variable_address << 4)
                    | uint8_t(val.mapping << 2)
                    | uint8_t(val.filtering);
        return out << std::bitset<8>(num);
    }
    return out;
}

std::istream& operator>>(std::istream& in, firewall& val) noexcept(false)
{
    std::string str;
    in >> str;

    auto num = std::stoul(str, nullptr, 2);
    val.nat = static_cast<bool>(num & 0x80);
    val.hairpin = static_cast<bool>(num & 0x40);
    val.random_port = static_cast<bool>(num & 0x20);
    val.variable_address = static_cast<bool>(num & 0x10);
    val.mapping = static_cast<firewall::relation>((num & 0x0C) >> 2);
    val.filtering = static_cast<firewall::relation>(num & 0x03);

    return in;
}

std::ostream& operator<<(std::ostream& out, const identity& val) noexcept(false)
{
    if (out.rdbuf())
        return out << val.owner + "/" + val.pin;
    return out;
}

std::istream& operator>>(std::istream& in, identity& val) noexcept(false)
{
    std::string str;
    in >> str;

    std::smatch match;
    if (!std::regex_match(str, match, std::regex("^([^/]*)/([^/]*)$")))
        throw boost::bad_lexical_cast();

    val.owner = match[1].str();
    val.pin = match[2].str();
    return in;
}

std::ostream& operator<<(std::ostream& out, const routing::favour& val) noexcept(false)
{
    switch (val)
    {
        case routing::direct:
            return out << "direct";
        case routing::bridge:
            return out << "bridge";
        case routing::either:
            return out << "either";
        default:
            break;
    }
    throw std::runtime_error("unknown favour value");
}

std::istream& operator>>(std::istream& in, routing::favour& val) noexcept(false)
{
    std::string str;
    in >> str;
    if (str == "direct" || str == "0")
        val = routing::direct;
    else if (str == "bridge" || str == "1")
        val = routing::bridge;
    else if (str == "either" || str == "2")
        val = routing::either;
    else
        throw std::runtime_error("unknown favour value");
    return in;
}

std::ostream& operator<<(std::ostream& out, const checkup& val) noexcept(false)
{
    switch (val)
    {
        case checkup::strict:
            return out << "strict";
        case checkup::faulty:
            return out << "faulty";
        case checkup::simple:
            return out << "simple";
        case checkup::noneed:
            return out << "noneed";
        default:
            break;
    }
    throw std::runtime_error("unknown checkup value");
}

std::istream& operator>>(std::istream& in, checkup& val) noexcept(false)
{
    std::string str;
    in >> str;
    if (str == "noneed" || str == "0")
        val = checkup::noneed;
    else if (str == "strict" || str == "1")
        val = checkup::strict;
    else if (str == "faulty" || str == "2")
        val = checkup::faulty;
    else if (str == "simple" || str == "3")
        val = checkup::simple;
    else
        throw std::runtime_error("unknown checkup value");
    return in;
}

std::pair<uint16_t, uint16_t> make_relay_variants(const reference& host, const reference& peer) noexcept(false)
{
    bool tcp_relay_capable = host.tcp.route != routing::direct && peer.tcp.route != routing::direct
                            && (!host.tcp.relay.address.is_unspecified() || !peer.tcp.relay.address.is_unspecified())
                            && !host.tcp.outer.address.is_unspecified() && !peer.tcp.outer.address.is_unspecified() 
                            && host.tcp.outer.address.is_v4() == peer.tcp.outer.address.is_v4() 
                            && host.tcp.outer.address.is_v4() == host.tcp.relay.address.is_v4();

    bool udp_relay_capable = host.udp.route != routing::direct && peer.udp.route != routing::direct
                            && (!host.udp.relay.address.is_unspecified() || !peer.udp.relay.address.is_unspecified())
                            && !host.udp.outer.address.is_unspecified() && !peer.udp.outer.address.is_unspecified() 
                            && host.udp.outer.address.is_v4() == peer.udp.outer.address.is_v4() 
                            && host.udp.outer.address.is_v4() == host.udp.relay.address.is_v4();

    uint16_t host_variants = 0;
    uint16_t peer_variants = 0;

    if (tcp_relay_capable)
    {
        bool host_tcp_hole_is_stable = host.tcp.force.mapping == firewall::independent && !host.tcp.force.variable_address;
        bool peer_tcp_hole_is_stable = peer.tcp.force.mapping == firewall::independent && !peer.tcp.force.variable_address;

        if (host_tcp_hole_is_stable)
        {
            if (host.qos.role == schema::server || host.qos.role == schema::either)
            {
                if ((host.qos.proto == protocol::ssl || host.qos.proto == protocol::any) && (host.qos.role == schema::server || !host.tcp.force.nat || host.tcp.force.filtering == firewall::independent))
                    host_variants |= SSL_SERVER;
                if ((host.qos.proto == protocol::tcp || host.qos.proto == protocol::any) && (host.qos.role == schema::server || !host.tcp.force.nat || host.tcp.force.filtering == firewall::independent))
                    host_variants |= TCP_SERVER;
            }
        }

        if (host.qos.role == schema::client || host.qos.role == schema::either)
        {
            if (host.qos.proto == protocol::ssl || host.qos.proto == protocol::any)
                host_variants |= SSL_CLIENT;
            if (host.qos.proto == protocol::tcp || host.qos.proto == protocol::any)
                host_variants |= TCP_CLIENT;
        }

        if (host.qos.role == schema::mutual || host.qos.role == schema::either)
        {
            if (host.qos.proto == protocol::ssl || host.qos.proto == protocol::any)
                host_variants |= SSL_MUTUAL;
            if (host.qos.proto == protocol::tcp || host.qos.proto == protocol::any)
                host_variants |= TCP_MUTUAL;
        }

        if (peer_tcp_hole_is_stable)
        {
            if (peer.qos.role == schema::server || peer.qos.role == schema::either)
            {
                if ((peer.qos.proto == protocol::ssl || peer.qos.proto == protocol::any) && (peer.qos.role == schema::server || !peer.tcp.force.nat || peer.tcp.force.filtering == firewall::independent))
                    peer_variants |= SSL_SERVER;
                if ((peer.qos.proto == protocol::tcp || peer.qos.proto == protocol::any) && (peer.qos.role == schema::server || !peer.tcp.force.nat || peer.tcp.force.filtering == firewall::independent))
                    peer_variants |= TCP_SERVER;
            }
        }

        if (peer.qos.role == schema::client || peer.qos.role == schema::either)
        {
            if (peer.qos.proto == protocol::ssl || peer.qos.proto == protocol::any)
                peer_variants |= SSL_CLIENT;
            if (peer.qos.proto == protocol::tcp || peer.qos.proto == protocol::any)
                peer_variants |= TCP_CLIENT;
        }

        if (peer.qos.role == schema::mutual || peer.qos.role == schema::either)
        {
            if (peer.qos.proto == protocol::ssl || peer.qos.proto == protocol::any)
                peer_variants |= SSL_MUTUAL;
            if (peer.qos.proto == protocol::tcp || peer.qos.proto == protocol::any)
                peer_variants |= TCP_MUTUAL;
        }
    }

    if (udp_relay_capable)
    {
        bool host_udp_hole_is_stable = host.udp.force.mapping == firewall::independent && !host.udp.force.variable_address;
        bool peer_udp_hole_is_stable = peer.udp.force.mapping == firewall::independent && !peer.udp.force.variable_address;

        if (host_udp_hole_is_stable)
        {
            if (host.qos.role == schema::server || host.qos.role == schema::either)
            {
                if (host.qos.proto == protocol::udp || host.qos.proto == protocol::any)
                    host_variants |= UDP_SERVER;
            }
        }

        if (host.qos.role == schema::client || host.qos.role == schema::either)
        {
            if (host.qos.proto == protocol::udp || host.qos.proto == protocol::any)
                host_variants |= UDP_CLIENT;
        }

        if (host.qos.role == schema::mutual || host.qos.role == schema::either)
        {
            if (host.qos.proto == protocol::udp || host.qos.proto == protocol::any)
                host_variants |= UDP_MUTUAL;
        }

        if (peer_udp_hole_is_stable)
        {
            if (peer.qos.role == schema::server || peer.qos.role == schema::either)
            {
                if (peer.qos.proto == protocol::udp || peer.qos.proto == protocol::any)
                    peer_variants |= UDP_SERVER;
            }
        }

        if (peer.qos.role == schema::client || peer.qos.role == schema::either)
        {
            if (peer.qos.proto == protocol::udp || peer.qos.proto == protocol::any)
                peer_variants |= UDP_CLIENT;
        }

        if (peer.qos.role == schema::mutual || peer.qos.role == schema::either)
        {
            if (peer.qos.proto == protocol::udp || peer.qos.proto == protocol::any)
                peer_variants |= UDP_MUTUAL;
        }
    }

    return std::make_pair(host_variants, peer_variants);
}

std::pair<uint16_t, uint16_t> make_direct_variants(const reference& host, const reference& peer) noexcept(false)
{
    bool tcp_capable = host.tcp.route != routing::bridge && peer.tcp.route != routing::bridge
                    && !host.tcp.outer.address.is_unspecified() && !peer.tcp.outer.address.is_unspecified() && host.tcp.outer.address.is_v4() == peer.tcp.outer.address.is_v4()
                    && (!host.tcp.force.variable_address || !peer.tcp.force.variable_address)
                    && (host.tcp.force.mapping == firewall::independent || peer.tcp.force.mapping == firewall::independent)
                    && (host.tcp.outer.address != peer.tcp.outer.address || (host.tcp.force.hairpin && peer.tcp.force.hairpin));
    bool udp_capable = host.udp.route != routing::bridge && peer.udp.route != routing::bridge
                    && !host.udp.outer.address.is_unspecified() && !peer.udp.outer.address.is_unspecified() && host.udp.outer.address.is_v4() == peer.udp.outer.address.is_v4()
                    && (!host.udp.force.variable_address || !peer.udp.force.variable_address)
                    && (host.udp.force.mapping == firewall::independent || peer.udp.force.mapping == firewall::independent)
                    && (host.udp.outer.address != peer.udp.outer.address || (host.udp.force.hairpin && peer.udp.force.hairpin));

    uint16_t host_variants = 0;
    uint16_t peer_variants = 0;

    if (tcp_capable)
    {
        bool host_tcp_hole_is_stable = host.tcp.force.mapping == firewall::independent && !host.tcp.force.variable_address;
        bool peer_tcp_hole_is_stable = peer.tcp.force.mapping == firewall::independent && !peer.tcp.force.variable_address;

        if (host_tcp_hole_is_stable)
        {
            if (host.qos.role == schema::server || host.qos.role == schema::either)
            {
                if ((host.qos.proto == protocol::ssl || host.qos.proto == protocol::any) && (host.qos.role == schema::server || !host.tcp.force.nat || host.tcp.force.filtering == firewall::independent))
                    host_variants |= SSL_SERVER;
                if ((host.qos.proto == protocol::tcp || host.qos.proto == protocol::any) && (host.qos.role == schema::server || !host.tcp.force.nat || host.tcp.force.filtering == firewall::independent))
                    host_variants |= TCP_SERVER;
            }
            if (host.qos.role == schema::mutual || host.qos.role == schema::either)
            {
                if (host.qos.proto == protocol::ssl || host.qos.proto == protocol::any)
                    host_variants |= SSL_MUTUAL;
                if (host.qos.proto == protocol::tcp || host.qos.proto == protocol::any)
                    host_variants |= TCP_MUTUAL;
            }
        }
        if (host_tcp_hole_is_stable || (peer_tcp_hole_is_stable && peer.tcp.force.filtering == firewall::independent))
        {
            if (host.qos.role == schema::client || host.qos.role == schema::either)
            {
                if (host.qos.proto == protocol::ssl || host.qos.proto == protocol::any)
                    host_variants |= SSL_CLIENT;
                if (host.qos.proto == protocol::tcp || host.qos.proto == protocol::any)
                    host_variants |= TCP_CLIENT;
            }
        }
        if (peer_tcp_hole_is_stable)
        {
            if (peer.qos.role == schema::server || peer.qos.role == schema::either)
            {
                if ((peer.qos.proto == protocol::ssl || peer.qos.proto == protocol::any) && (peer.qos.role == schema::server || !peer.tcp.force.nat || peer.tcp.force.filtering == firewall::independent))
                    peer_variants |= SSL_SERVER;
                if ((peer.qos.proto == protocol::tcp || peer.qos.proto == protocol::any) && (peer.qos.role == schema::server || !peer.tcp.force.nat || peer.tcp.force.filtering == firewall::independent))
                    peer_variants |= TCP_SERVER;
            }
            if (peer.qos.role == schema::mutual || peer.qos.role == schema::either)
            {
                if (peer.qos.proto == protocol::ssl || peer.qos.proto == protocol::any)
                    peer_variants |= SSL_MUTUAL;
                if (peer.qos.proto == protocol::tcp || peer.qos.proto == protocol::any)
                    peer_variants |= TCP_MUTUAL;
            }
        }
        if (peer_tcp_hole_is_stable || (host_tcp_hole_is_stable && host.tcp.force.filtering == firewall::independent))
        {
            if (peer.qos.role == schema::client || peer.qos.role == schema::either)
            {
                if (peer.qos.proto == protocol::ssl || peer.qos.proto == protocol::any)
                    peer_variants |= SSL_CLIENT;
                if (peer.qos.proto == protocol::tcp || peer.qos.proto == protocol::any)
                    peer_variants |= TCP_CLIENT;
            }
        }
    }

    if (udp_capable)
    {
        bool host_udp_hole_is_stable = host.udp.force.mapping == firewall::independent && !host.udp.force.variable_address;
        bool peer_udp_hole_is_stable = peer.udp.force.mapping == firewall::independent && !peer.udp.force.variable_address;

        if (host_udp_hole_is_stable)
        {
            if (host.qos.role == schema::server || host.qos.role == schema::either)
            {
                if (host.qos.proto == protocol::udp || host.qos.proto == protocol::any)
                    host_variants |= UDP_SERVER;
            }
            if (host.qos.role == schema::mutual || host.qos.role == schema::either)
            {
                if (host.qos.proto == protocol::udp || host.qos.proto == protocol::any)
                    host_variants |= UDP_MUTUAL;
            }
        }
        if (host_udp_hole_is_stable || (peer_udp_hole_is_stable && peer.udp.force.filtering == firewall::independent))
        {
            if (host.qos.role == schema::client || host.qos.role == schema::either)
            {
                if (host.qos.proto == protocol::udp || host.qos.proto == protocol::any)
                    host_variants |= UDP_CLIENT;
            }
        }
        if (peer_udp_hole_is_stable)
        {
            if (peer.qos.role == schema::server || peer.qos.role == schema::either)
            {
                if (peer.qos.proto == protocol::udp || peer.qos.proto == protocol::any)
                    peer_variants |= UDP_SERVER;
            }
            if (peer.qos.role == schema::mutual || peer.qos.role == schema::either)
            {
                if (peer.qos.proto == protocol::udp || peer.qos.proto == protocol::any)
                    peer_variants |= UDP_MUTUAL;
            }
        }
        if (peer_udp_hole_is_stable || (host_udp_hole_is_stable && host.udp.force.filtering == firewall::independent))
        {
            if (peer.qos.role == schema::client || peer.qos.role == schema::either)
            {
                if (peer.qos.proto == protocol::udp || peer.qos.proto == protocol::any)
                    peer_variants |= UDP_CLIENT;
            }
        }
    }

    return std::make_pair(host_variants, peer_variants);
}

bool make_contract(bool relay, const location& bind, const reference& host, const reference& peer, bool accept, contract& info) noexcept(false)
{
    auto [host_variants, peer_variants] = relay 
                                        ? make_relay_variants(host, peer)
                                        : make_direct_variants(host, peer);

    uint16_t lhs = accept ? host_variants : peer_variants;
    uint16_t rhs = accept ? peer_variants : host_variants;

    if ((lhs & SSL_SERVER) && (rhs & SSL_CLIENT))
        info.qos = { protocol::ssl, accept ? schema::server : schema::client };
    else if ((lhs & SSL_CLIENT) && (rhs & SSL_SERVER))
        info.qos = { protocol::ssl, accept ? schema::client : schema::server };
    else if ((lhs & TCP_SERVER) && (rhs & TCP_CLIENT))
        info.qos = { protocol::tcp, accept ? schema::server : schema::client };
    else if ((lhs & TCP_CLIENT) && (rhs & TCP_SERVER))
        info.qos = { protocol::tcp, accept ? schema::client : schema::server };
    else if ((lhs & UDP_SERVER) && (rhs & UDP_CLIENT))
        info.qos = { protocol::udp, accept ? schema::server : schema::client };
    else if ((lhs & UDP_CLIENT) && (rhs & UDP_SERVER))
        info.qos = { protocol::udp, accept ? schema::client : schema::server };
    else if (relay && (lhs & SSL_MUTUAL) && (rhs & SSL_MUTUAL))
        info.qos = { protocol::ssl, schema::mutual };
    else if (relay && (lhs & TCP_MUTUAL) && (rhs & TCP_MUTUAL))
        info.qos = { protocol::tcp, schema::mutual };
    else if ((lhs & UDP_MUTUAL) && (rhs & UDP_MUTUAL))
        info.qos = { protocol::udp, schema::mutual };
    else if ((lhs & TCP_MUTUAL) && (rhs & TCP_MUTUAL))
        info.qos = { protocol::tcp, schema::mutual };
    else if ((lhs & SSL_MUTUAL) && (rhs & SSL_MUTUAL))
        info.qos = { protocol::ssl, schema::mutual };
    else
        return false;

    auto correct_outer = [](const endpoint& outer, firewall force)
    {
        return endpoint {
            force.variable_address 
                ? (outer.address.is_v4() ? boost::asio::ip::address(boost::asio::ip::address_v4()) : boost::asio::ip::address(boost::asio::ip::address_v6()))
                : outer.address,
            force.mapping == firewall::independent
                ? outer.port
                : static_cast<uint16_t>(0)
        };
    };

    info.secret = host.puzzle ^ peer.puzzle;
    info.inner = info.qos.proto == protocol::udp ? bind.udp : bind.tcp;
    info.outer = info.qos.proto == protocol::udp ? correct_outer(host.udp.outer, host.udp.force) : correct_outer(host.tcp.outer, host.tcp.force);

    if (relay)
    {
        auto udp_relay = (accept && !host.udp.relay.address.is_unspecified()) || peer.udp.relay.address.is_unspecified() ? host.udp.relay : peer.udp.relay;
        auto tcp_relay = (accept && !host.tcp.relay.address.is_unspecified()) || peer.tcp.relay.address.is_unspecified() ? host.tcp.relay : peer.tcp.relay;
        info.alien = info.qos.proto == protocol::udp ? udp_relay : tcp_relay;
    }
    else
    {
        info.alien = info.qos.proto == protocol::udp ? correct_outer(peer.udp.outer, peer.udp.force) : correct_outer(peer.tcp.outer, peer.tcp.force);
    }

    _inf_ << "contract: qos=" << info.qos << " inner=" << info.inner << " outer=" << info.outer << " alien=" << info.alien << " relay=" << relay;

    return true;
}

contract make_contract(const location& bind, const reference& host, const reference& peer, bool accept) noexcept(false)
{
    contract info;

    bool ok = make_contract(false, bind, host, peer, accept, info) || make_contract(true, bind, host, peer, accept, info);
    if (!ok)
        throw std::runtime_error("unsuitable conditions");

    return info;
}

void explore_network(boost::asio::io_context& io, const location& bind, const location& stun, checkup mode, const std::function<void(const traverse&)>& handler, const std::function<void(const std::string&)>& failure) noexcept(true)
{
    boost::asio::spawn(io, [&io, bind, stun, mode, handler, failure](boost::asio::yield_context yield)
    {
        _inf_ << "explore network...";

        try
        {
            auto client = plexus::create_stun_client(io, stun, bind);
            handler(client->make_traverse(yield, protocol::any, mode));
        }
        catch (const std::exception& e)
        {
            _err_ << "explore network error: " << e.what();

            if (failure)
                failure(e.what());
        }
    }, boost::asio::detached);
}

void spawn_accept(boost::asio::io_context& io, const options& config, const identity& host, const identity& peer, const connector& connect, const fallback& failure) noexcept(true)
{
    auto handler = [&io, config, connect, failure](boost::asio::yield_context yield, std::shared_ptr<plexus::pipe> pipe)
    {
        auto peer = pipe->peer();
        auto host = pipe->host();

        _inf_ << "accept: app=" << config.app << " qos=" << config.qos << " host=" << host << " peer=" << peer;

        try
        {
            auto broker = plexus::create_link_broker(io, config.stun, config.bind, config.hops, config.relay);
            auto pass = broker->make_traverse(yield, config.qos.proto, config.mode);

            auto faraway = pipe->pull_request(yield);
            auto gateway = reference {
                reference::mapping { pass.udp.outer, pass.udp.force, config.qos.proto <= protocol::udp && config.route.udp != routing::direct && faraway.udp.relay.address.is_unspecified() ? broker->get_udp_relay(yield) : endpoint {}, config.route.udp },
                reference::mapping { pass.tcp.outer, pass.tcp.force, config.qos.proto != protocol::udp && config.route.tcp != routing::direct && faraway.tcp.relay.address.is_unspecified() ? broker->get_tcp_relay(yield) : endpoint {}, config.route.tcp },
                config.qos,
                utils::random<uint64_t>(),
                boost::posix_time::microsec_clock::universal_time()
            };
            pipe->push_response(yield, gateway);

            connect(host, peer, broker->await_peer(yield, gateway, faraway));
        }
        catch (const std::exception& e)
        {
            _err_ << "accept: " << e.what();

            if (failure)
                failure(host, peer, e.what());
        }
    };

    config.mediator.index() == 0
        ? spawn_accept(io, context<emailer>(config.app, config.repo, std::get<emailer>(config.mediator)), host, peer, handler)
        : spawn_accept(io, context<dhtnode>(config.app, config.repo, std::get<dhtnode>(config.mediator)), host, peer, handler);
}

void spawn_invite(boost::asio::io_context& io, const options& config, const identity& host, const identity& peer, const connector& connect, const fallback& failure) noexcept(true)
{
    auto handler = [&io, config, connect, failure](boost::asio::yield_context yield, std::shared_ptr<plexus::pipe> pipe)
    {
        auto peer = pipe->peer();
        auto host = pipe->host();

        _inf_ << "invite: app=" << config.app << " qos=" << config.qos << " host=" << host << " peer=" << peer;

        try
        {
            auto broker = plexus::create_link_broker(io, config.stun, config.bind, config.hops, config.relay);
            auto pass = broker->make_traverse(yield, config.qos.proto, config.mode);

            auto gateway = reference { 
                reference::mapping { pass.udp.outer, pass.udp.force, config.qos.proto <= protocol::udp && config.route.udp != routing::direct ? broker->get_udp_relay(yield) : endpoint {}, config.route.udp },
                reference::mapping { pass.tcp.outer, pass.tcp.force, config.qos.proto != protocol::udp && config.route.tcp != routing::direct ? broker->get_tcp_relay(yield) : endpoint {}, config.route.tcp },
                config.qos,
                utils::random<uint64_t>(),
                boost::posix_time::microsec_clock::universal_time()
            };
            pipe->push_request(yield, gateway);
            auto faraway = pipe->pull_response(yield);

            connect(host, peer, broker->touch_peer(yield, gateway, faraway));
        }
        catch (const std::exception& e)
        {
            _err_ << "invite: " << e.what();

            if (failure)
                failure(host, peer, e.what());
        }
    };

    config.mediator.index() == 0
        ? spawn_invite(io, context<emailer>(config.app, config.repo, std::get<emailer>(config.mediator)), host, peer, handler)
        : spawn_invite(io, context<dhtnode>(config.app, config.repo, std::get<dhtnode>(config.mediator)), host, peer, handler);
}

void forward_advent(boost::asio::io_context& io, const rendezvous& mediator, const std::string& app, const std::string& repo, const identity& host, const identity& peer, const observer& handler, const fallback& failure) noexcept(true)
{
    _inf_ << "forward advent: app=" << app << " host=" << host << " peer=" << peer;

    mediator.index() == 0
        ? forward_advent(io, context<emailer>(app, repo, std::get<emailer>(mediator)), host, peer, handler, failure)
        : forward_advent(io, context<dhtnode>(app, repo, std::get<dhtnode>(mediator)), host, peer, handler, failure);
}

void receive_advent(boost::asio::io_context& io, const rendezvous& mediator, const std::string& app, const std::string& repo, const identity& host, const identity& peer, const observer& handler, const fallback& failure) noexcept(true)
{
    _inf_ << "receive advent: app=" << app << " host=" << host << " peer=" << peer;

    mediator.index() == 0
        ? receive_advent(io, context<emailer>(app, repo, std::get<emailer>(mediator)), host, peer, handler, failure)
        : receive_advent(io, context<dhtnode>(app, repo, std::get<dhtnode>(mediator)), host, peer, handler, failure);
}

}
