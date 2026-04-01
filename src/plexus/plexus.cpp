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

contract make_contract(const endpoint& udp_bind, const endpoint& tcp_bind, const reference& host_pass, const reference& peer_pass, bool accept) noexcept(false)
{
    static constexpr uint8_t SSL_SERVER = 0x01;
    static constexpr uint8_t SSL_CLIENT = 0x02;
    static constexpr uint8_t TCP_SERVER = 0x04;
    static constexpr uint8_t TCP_CLIENT = 0x08;
    static constexpr uint8_t UDP_SERVER = 0x10;
    static constexpr uint8_t UDP_CLIENT = 0x20;
    static constexpr uint8_t STABLE_UDP_HOLE = 0x40;
    static constexpr uint8_t STABLE_TCP_HOLE = 0x80;

    bool tcp_available = host_pass.tcp.outer != endpoint{} && peer_pass.tcp.outer != endpoint{}
                      && (host_pass.tcp.outer.address != peer_pass.tcp.outer.address || (host_pass.tcp.force.hairpin && peer_pass.tcp.force.hairpin));
    bool udp_available = host_pass.udp.outer != endpoint{} && peer_pass.udp.outer != endpoint{}
                      && (host_pass.udp.outer.address != peer_pass.udp.outer.address || (host_pass.udp.force.hairpin && peer_pass.udp.force.hairpin));

    if (!tcp_available && !udp_available)
        throw std::runtime_error("bad network conditions");

    contract info;

    uint8_t host_variants = 0;
    uint8_t peer_variants = 0;

    if (tcp_available)
    {
        if (host_pass.tcp.force.mapping == firewall::independent && !host_pass.tcp.force.variable_address)
        {
            host_variants |= STABLE_TCP_HOLE;
            if (host_pass.qos.role == relation::server || host_pass.qos.role == relation::either)
            {
                if (host_pass.qos.proto == protocol::ssl || (host_pass.qos.proto == protocol::any && !host_pass.tcp.force.nat))
                    host_variants |= SSL_SERVER;
                if (host_pass.qos.proto == protocol::tcp || (host_pass.qos.proto == protocol::any && !host_pass.tcp.force.nat))
                    host_variants |= TCP_SERVER;
            }
        }
        if (host_pass.tcp.force.mapping == firewall::independent || peer_pass.tcp.force.filtering == firewall::independent)
        {
            if (host_pass.qos.role != relation::server)
            {
                if (host_pass.qos.proto == protocol::ssl || host_pass.qos.proto == protocol::any)
                    host_variants |= SSL_CLIENT;
                if (host_pass.qos.proto == protocol::tcp || host_pass.qos.proto == protocol::any)
                    host_variants |= TCP_CLIENT;
            }
        }
        if (peer_pass.tcp.force.mapping == firewall::independent && !peer_pass.tcp.force.variable_address)
        {
            peer_variants |= STABLE_TCP_HOLE;
            if (peer_pass.qos.role == relation::server || peer_pass.qos.role == relation::either)
            {
                if (peer_pass.qos.proto == protocol::ssl || (peer_pass.qos.proto == protocol::any && !peer_pass.tcp.force.nat))
                    peer_variants |= SSL_SERVER;
                if (peer_pass.qos.proto == protocol::tcp || (peer_pass.qos.proto == protocol::any && !peer_pass.tcp.force.nat))
                    peer_variants |= TCP_SERVER;
            }
        }
        if (peer_pass.tcp.force.mapping == firewall::independent || host_pass.tcp.force.filtering == firewall::independent)
        {
            if (peer_pass.qos.role != relation::server)
            {
                if (peer_pass.qos.proto == protocol::ssl || peer_pass.qos.proto == protocol::any)
                    peer_variants |= SSL_CLIENT;
                if (peer_pass.qos.proto == protocol::tcp || peer_pass.qos.proto == protocol::any)
                    peer_variants |= TCP_CLIENT;
            }
        }
    }

    if (udp_available)
    {
        if (host_pass.udp.force.mapping == firewall::independent && !host_pass.udp.force.variable_address)
        {
            host_variants |= STABLE_UDP_HOLE;
            if (host_pass.qos.role == relation::server || host_pass.qos.role == relation::either)
            {
                if (host_pass.qos.proto == protocol::udp || host_pass.qos.proto == protocol::any)
                    host_variants |= UDP_SERVER;
            }
        }
        if (host_pass.udp.force.mapping == firewall::independent || peer_pass.udp.force.filtering == firewall::independent)
        {
            if (host_pass.qos.role != relation::server)
            {
                if (host_pass.qos.proto == protocol::udp || host_pass.qos.proto == protocol::any)
                    host_variants |= UDP_CLIENT;
            }
        }
        if (peer_pass.udp.force.mapping == firewall::independent && !peer_pass.udp.force.variable_address)
        {
            peer_variants |= STABLE_UDP_HOLE;
            if (peer_pass.qos.role == relation::server || peer_pass.qos.role == relation::either)
            {
                if (peer_pass.qos.proto == protocol::udp || peer_pass.qos.proto == protocol::any)
                    peer_variants |= UDP_SERVER;
            }
        }
        if (peer_pass.udp.force.mapping == firewall::independent || host_pass.udp.force.filtering == firewall::independent)
        {
            if (peer_pass.qos.role != relation::server)
            {
                if (peer_pass.qos.proto == protocol::udp || peer_pass.qos.proto == protocol::any)
                    peer_variants |= UDP_CLIENT;
            }
        }
    }

    uint8_t lhs = accept ? host_variants : peer_variants;
    uint8_t rhs = accept ? peer_variants : host_variants;

    if ((lhs & SSL_SERVER) && (rhs & SSL_CLIENT))
        info.qos = { protocol::ssl, accept ? relation::server : relation::client };
    else if ((lhs & SSL_CLIENT) && (rhs & SSL_SERVER))
        info.qos = { protocol::ssl, accept ? relation::client : relation::server };
    else if ((lhs & TCP_SERVER) && (rhs & TCP_CLIENT))
        info.qos = { protocol::tcp, accept ? relation::server : relation::client };
    else if ((lhs & TCP_CLIENT) && (rhs & TCP_SERVER))
        info.qos = { protocol::tcp, accept ? relation::client : relation::server };
    else if ((lhs & UDP_SERVER) && (rhs & UDP_CLIENT))
        info.qos = { protocol::udp, accept ? relation::server : relation::client };
    else if ((lhs & UDP_CLIENT) && (rhs & UDP_SERVER))
        info.qos = { protocol::udp, accept ? relation::client : relation::server };
    else if ((lhs & UDP_CLIENT) && (lhs & STABLE_UDP_HOLE) && (rhs & UDP_CLIENT) && (rhs & STABLE_UDP_HOLE))
        info.qos = { protocol::udp, relation::mutual };
    else if ((lhs & SSL_CLIENT) && (lhs & STABLE_TCP_HOLE) && (rhs & SSL_CLIENT) && (rhs & STABLE_TCP_HOLE))
        info.qos = { protocol::ssl, relation::mutual };
    else if ((lhs & TCP_CLIENT) && (lhs & STABLE_TCP_HOLE) && (rhs & TCP_CLIENT) && (rhs & STABLE_TCP_HOLE))
        info.qos = { protocol::tcp, relation::mutual };
    else
        throw std::runtime_error("unsuitable conditions");

    info.inner = info.qos.proto == protocol::udp ? udp_bind : tcp_bind;
    info.outer = info.qos.proto == protocol::udp ? host_pass.udp.outer : host_pass.tcp.outer;
    info.alien = info.qos.proto == protocol::udp ? peer_pass.udp.outer : peer_pass.tcp.outer;
    info.secret = host_pass.puzzle ^ peer_pass.puzzle;

    _inf_ << "contarct: qos=" << info.qos << " inner=" << info.inner << " outer=" << info.outer << " alien=" << info.alien;

    return info;
}

void explore_network(boost::asio::io_context& io, const endpoint& udp_bind, const endpoint& tcp_bind, const endpoint& udp_stun, const endpoint& tcp_stun, const std::function<void(const traverse&)>& handler, const std::function<void(const std::string&)>& failure) noexcept(true)
{
    boost::asio::spawn(io, [&io, udp_bind, tcp_bind, udp_stun, tcp_stun, handler, failure](boost::asio::yield_context yield)
    {
        _inf_ << "exploring network...";

        try
        {
            auto client = plexus::create_stun_client(io, udp_stun, tcp_stun, udp_bind, tcp_bind);
            auto pass = client->make_traverse(yield, protocol::any);

            handler(pass);
        }
        catch (const std::exception& e)
        {
            _err_ << "exploring network error: " << e.what();

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

        _inf_ << "accepting: app=" << config.app << " qos=" << config.qos << " host=" << host << " peer=" << peer;

        try
        {
            auto broker = plexus::create_sync_broker(io, config.udp_stun, config.tcp_stun, config.udp_bind, config.tcp_bind, config.hops);
            auto pass = broker->make_traverse(yield, config.qos.proto);

            reference faraway = pipe->pull_request(yield);
            reference gateway = { { pass.udp.outer, pass.udp.force }, { pass.tcp.outer, pass.tcp.force }, config.qos, plexus::utils::random<uint64_t>() };
            pipe->push_response(yield, gateway);

            connect(host, peer, broker->await_peer(yield, gateway, faraway));
        }
        catch (const std::exception& e)
        {
            _err_ << "accepting: " << e.what();

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

        _inf_ << "inviting: app=" << config.app << " qos=" << config.qos << " host=" << host << " peer=" << peer;

        try
        {
            auto broker = plexus::create_sync_broker(io, config.udp_stun, config.tcp_stun, config.udp_bind, config.tcp_bind, config.hops);
            auto pass = broker->make_traverse(yield, config.qos.proto);

            plexus::reference gateway = { { pass.udp.outer, pass.udp.force }, { pass.tcp.outer, pass.tcp.force }, config.qos, plexus::utils::random<uint64_t>() };
            pipe->push_request(yield, gateway);
            plexus::reference faraway = pipe->pull_response(yield);

            connect(host, peer, broker->touch_peer(yield, gateway, faraway));
        }
        catch (const std::exception& e)
        {
            _err_ << "inviting: " << e.what();

            if (failure)
                failure(pipe->host(), pipe->peer(), e.what());
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
