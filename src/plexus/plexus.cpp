/*
 * Copyright (c) 2022 Novemus Band. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 */

#include <plexus/plexus.h>
#include <plexus/features.h>
#include <plexus/utils.h>
#include <wormhole/logger.h>
#include <bitset>

namespace plexus {

std::string firewall::to_string(const firewall& val) noexcept(false)
{
    return std::bitset<8>(firewall::to_number(val)).to_string();
}

firewall firewall::from_string(const std::string& str) noexcept(false)
{
    return firewall::from_number(std::stoul(str, nullptr, 2));
}

uint8_t firewall::to_number(const firewall& val) noexcept(true)
{
    return uint8_t(val.nat << 7)
         | uint8_t(val.hairpin << 6)
         | uint8_t(val.random_port << 5)
         | uint8_t(val.variable_address << 4)
         | uint8_t(val.mapping << 2)
         | uint8_t(val.filtering);
}

firewall firewall::from_number(uint8_t num) noexcept(true)
{
    return firewall {
        static_cast<bool>(num & 0x80),
        static_cast<bool>(num & 0x40),
        static_cast<bool>(num & 0x20),
        static_cast<bool>(num & 0x10),
        static_cast<firewall::linkage>((num & 0x0C) >> 2),
        static_cast<firewall::linkage>(num & 0x03)
    };
}

std::ostream& operator<<(std::ostream& out, const firewall& val) noexcept(false)
{
    if (out.rdbuf())
        return out << firewall::to_string(val);
    return out;
}

std::istream& operator>>(std::istream& in, firewall& val) noexcept(false)
{
    std::string str;
    in >> str;
    val = firewall::from_string(str);
    return in;
}

std::string identity::to_string(const identity& val) noexcept(false)
{
    return val.owner + "/" + val.pin;
}

identity identity::from_string(const std::string& str) noexcept(false)
{
    std::smatch match;
    if (std::regex_match(str, match, std::regex("^([^/]*)/([^/]*)$")))
        return identity {match[1].str(), match[2].str()};

    throw boost::bad_lexical_cast();
}

std::ostream& operator<<(std::ostream& out, const identity& val) noexcept(false)
{
    if (out.rdbuf())
        return out << identity::to_string(val);
    return out;
}

std::istream& operator>>(std::istream& in, identity& val) noexcept(false)
{
    std::string str;
    in >> str;
    val = identity::from_string(str);
    return in;
}

contract make_contract(const location& bind, const reference& host, const reference& peer, bool accept) noexcept(false)
{
    static constexpr uint16_t SSL_SERVER = 0x0001;
    static constexpr uint16_t SSL_CLIENT = 0x0002;
    static constexpr uint16_t SSL_MUTUAL = 0x0004;
    static constexpr uint16_t TCP_SERVER = 0x0008;
    static constexpr uint16_t TCP_CLIENT = 0x0010;
    static constexpr uint16_t TCP_MUTUAL = 0x0020;
    static constexpr uint16_t UDP_SERVER = 0x0040;
    static constexpr uint16_t UDP_CLIENT = 0x0080;
    static constexpr uint16_t UDP_MUTUAL = 0x0100;

    bool tcp_capable = host.tcp.outer != endpoint{} && peer.tcp.outer != endpoint{}
                      && (!host.tcp.force.variable_address || !peer.tcp.force.variable_address)
                      && (host.tcp.force.mapping == firewall::independent || peer.tcp.force.mapping == firewall::independent)
                      && (host.tcp.outer.address != peer.tcp.outer.address || (host.tcp.force.hairpin && peer.tcp.force.hairpin));
    bool udp_capable = host.udp.outer != endpoint{} && peer.udp.outer != endpoint{}
                      && (!host.udp.force.variable_address || !peer.udp.force.variable_address)
                      && (host.udp.force.mapping == firewall::independent || peer.udp.force.mapping == firewall::independent)
                      && (host.udp.outer.address != peer.udp.outer.address || (host.udp.force.hairpin && peer.udp.force.hairpin));

    if (!tcp_capable && !udp_capable)
        throw std::runtime_error("bad network conditions");

    contract info;

    uint16_t host_variants = 0;
    uint16_t peer_variants = 0;

    if (tcp_capable)
    {
        if (host.tcp.force.mapping == firewall::independent && !host.tcp.force.variable_address)
        {
            if (host.qos.role == schema::server || host.qos.role == schema::either)
            {
                if ((host.qos.proto == protocol::ssl || host.qos.proto == protocol::any) && (host.qos.role == schema::server || !host.tcp.force.nat || host.tcp.force.filtering == firewall::independent))
                    host_variants |= SSL_SERVER;
                if ((host.qos.proto == protocol::tcp || host.qos.proto == protocol::any) && (host.qos.role == schema::server || !host.tcp.force.nat || host.tcp.force.filtering == firewall::independent))
                    host_variants |= TCP_SERVER;
            }
        }
        if (host.tcp.force.mapping == firewall::independent || peer.tcp.force.filtering == firewall::independent)
        {
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
        }
        if (peer.tcp.force.mapping == firewall::independent && !peer.tcp.force.variable_address)
        {
            if (peer.qos.role == schema::server || peer.qos.role == schema::either)
            {
                if ((peer.qos.proto == protocol::ssl || peer.qos.proto == protocol::any) && (peer.qos.role == schema::server || !peer.tcp.force.nat || peer.tcp.force.filtering == firewall::independent))
                    peer_variants |= SSL_SERVER;
                if ((peer.qos.proto == protocol::tcp || peer.qos.proto == protocol::any) && (peer.qos.role == schema::server || !peer.tcp.force.nat || peer.tcp.force.filtering == firewall::independent))
                    peer_variants |= TCP_SERVER;
            }
        }
        if (peer.tcp.force.mapping == firewall::independent || host.tcp.force.filtering == firewall::independent)
        {
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
    }

    if (udp_capable)
    {
        if (host.udp.force.mapping == firewall::independent && !host.udp.force.variable_address)
        {
            if (host.qos.role == schema::server || host.qos.role == schema::either)
            {
                if (host.qos.proto == protocol::udp || host.qos.proto == protocol::any)
                    host_variants |= UDP_SERVER;
            }
        }
        if (host.udp.force.mapping == firewall::independent || peer.udp.force.filtering == firewall::independent)
        {
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
        }
        if (peer.udp.force.mapping == firewall::independent && !peer.udp.force.variable_address)
        {
            if (peer.qos.role == schema::server || peer.qos.role == schema::either)
            {
                if (peer.qos.proto == protocol::udp || peer.qos.proto == protocol::any)
                    peer_variants |= UDP_SERVER;
            }
        }
        if (peer.udp.force.mapping == firewall::independent || host.udp.force.filtering == firewall::independent)
        {
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
    }

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
    else if ((lhs & UDP_MUTUAL) && (rhs & UDP_MUTUAL))
        info.qos = { protocol::udp, schema::mutual };
    else if ((lhs & TCP_MUTUAL) && (rhs & TCP_MUTUAL))
        info.qos = { protocol::tcp, schema::mutual };
    else if ((lhs & SSL_MUTUAL) && (rhs & SSL_MUTUAL))
        info.qos = { protocol::ssl, schema::mutual };
    else
        throw std::runtime_error("unsuitable conditions");

    info.inner = info.qos.proto == protocol::udp ? bind.udp : bind.tcp;
    info.outer = info.qos.proto == protocol::udp ? host.udp.outer : host.tcp.outer;
    info.alien = info.qos.proto == protocol::udp ? peer.udp.outer : peer.tcp.outer;
    info.secret = host.puzzle ^ peer.puzzle;

    _inf_ << "contract: qos=" << info.qos << " inner=" << info.inner << " outer=" << info.outer << " alien=" << info.alien;

    return info;
}

void explore_network(boost::asio::io_context& io, const location& bind, const location& stun, const std::function<void(const traverse&)>& handler, const std::function<void(const std::string&)>& failure) noexcept(true)
{
    boost::asio::spawn(io, [&io, bind, stun, handler, failure](boost::asio::yield_context yield)
    {
        _inf_ << "explore network...";

        try
        {
            auto client = plexus::create_stun_client(io, stun, bind);
            handler(client->make_traverse(yield, protocol::any));
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
            auto broker = plexus::create_sync_broker(io, config.stun, config.bind, config.hops);
            auto pass = broker->make_traverse(yield, config.qos.proto);

            auto faraway = pipe->pull_request(yield);
            auto gateway = reference { 
                reference::map { pass.udp.outer, pass.udp.force },
                reference::map { pass.tcp.outer, pass.tcp.force },
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
            auto broker = plexus::create_sync_broker(io, config.stun, config.bind, config.hops);
            auto pass = broker->make_traverse(yield, config.qos.proto);

            auto gateway = reference { 
                reference::map { pass.udp.outer, pass.udp.force },
                reference::map { pass.tcp.outer, pass.tcp.force },
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
