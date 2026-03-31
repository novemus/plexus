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

contract make_contract(const traverse& hole, const criteria& qos, uint64_t puzzle, bool accept, const reference& peer) noexcept(false)
{
    static constexpr uint8_t SSL_SERVER = 0x01;
    static constexpr uint8_t SSL_CLIENT = 0x02;
    static constexpr uint8_t TCP_SERVER = 0x04;
    static constexpr uint8_t TCP_CLIENT = 0x08;
    static constexpr uint8_t UDP_SERVER = 0x10;
    static constexpr uint8_t UDP_CLIENT = 0x20;

    if ((!hole.force.hairpin || !peer.force.hairpin) && hole.mapping.address == peer.mapping.address)
        throw std::runtime_error("hairpin is not supported");

    contract info;

    uint8_t host_variants = 0;
    if (hole.force.mapping == firewall::independent && !hole.force.variable_address)
    {
        if (qos.role == relation::server || qos.role == relation::either)
        {
            if (qos.proto == protocol::ssl || (qos.proto == protocol::any && !hole.force.nat))
                host_variants |= SSL_SERVER;
            if (qos.proto == protocol::tcp || (qos.proto == protocol::any && !hole.force.nat))
                host_variants |= TCP_SERVER;
            if (qos.proto == protocol::udp || qos.proto == protocol::any)
                host_variants |= UDP_SERVER;
        }
    }
    if (hole.force.mapping == firewall::independent || peer.force.filtering == firewall::independent)
    {
        if (qos.role == relation::client || qos.role == relation::either)
        {
            if (qos.proto == protocol::ssl || qos.proto == protocol::any)
                host_variants |= SSL_CLIENT;
            if (qos.proto == protocol::tcp || qos.proto == protocol::any)
                host_variants |= TCP_CLIENT;
            if (qos.proto == protocol::udp || qos.proto == protocol::any)
                host_variants |= UDP_CLIENT;
        }
    }

    uint8_t peer_variants = 0;
    if (peer.force.mapping == firewall::independent && !peer.force.variable_address)
    {
        if (peer.qos.role == relation::server || peer.qos.role == relation::either)
        {
            if (peer.qos.proto == protocol::ssl || (peer.qos.proto == protocol::any && !peer.force.nat))
                peer_variants |= SSL_SERVER;
            if (peer.qos.proto == protocol::tcp || (peer.qos.proto == protocol::any && !peer.force.nat))
                peer_variants |= TCP_SERVER;
            if (peer.qos.proto == protocol::udp || peer.qos.proto == protocol::any)
                peer_variants |= UDP_SERVER;
        }
    }
    if (peer.force.mapping == firewall::independent || hole.force.filtering == firewall::independent)
    {
        if (peer.qos.role == relation::client || peer.qos.role == relation::either)
        {
            if (peer.qos.proto == protocol::ssl || peer.qos.proto == protocol::any)
                peer_variants |= SSL_CLIENT;
            if (peer.qos.proto == protocol::tcp || peer.qos.proto == protocol::any)
                peer_variants |= TCP_CLIENT;
            if (peer.qos.proto == protocol::udp || peer.qos.proto == protocol::any)
                peer_variants |= UDP_CLIENT;
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
    else
        throw std::runtime_error("unsuitable conditions");

    info.gateway = hole.hosting;
    info.mapping = hole.mapping;
    info.faraway = peer.mapping;
    info.secret = puzzle ^ peer.puzzle;

    return info;
}

void explore_network(boost::asio::io_context& io, const endpoint& bind, const endpoint& stun, const std::function<void(const traverse&)>& handler, const std::function<void(const std::string&)>& failure) noexcept(true)
{
    boost::asio::spawn(io, [&io, bind, stun, handler, failure](boost::asio::yield_context yield)
    {
        _inf_ << "exploring network by stun " << stun << " from " << bind;

        try
        {
            auto client = plexus::create_stun_client(io, stun, bind);
            auto hole = client->explore_network(yield);

            handler(hole);
        }
        catch (const std::exception& e)
        {
            _err_ << "exploring network by stun " << stun << " from " << bind << " error: " << e.what();

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
            auto binder = plexus::create_stun_binder(io, config.stun, config.bind, config.hops);

            auto hole = binder->explore_network(yield);
            reference faraway = pipe->pull_request(yield);
            reference gateway = { hole.mapping, hole.force, config.qos, plexus::utils::random<uint64_t>() };
            pipe->push_response(yield, gateway);

            auto info = make_contract(hole, config.qos, gateway.puzzle, true, faraway);
            binder->await_peer(yield, faraway.mapping, faraway.puzzle ^ gateway.puzzle).reset();

            connect(host, peer, info);
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
            auto binder = plexus::create_stun_binder(io, config.stun, config.bind, config.hops);

            auto hole = binder->explore_network(yield);
            plexus::reference gateway = { hole.mapping, hole.force, config.qos, plexus::utils::random<uint64_t>() };
            pipe->push_request(yield, gateway);
            plexus::reference faraway = pipe->pull_response(yield);

            auto info = make_contract(hole, config.qos, gateway.puzzle, false, faraway);
            binder->reach_peer(yield, faraway.mapping, faraway.puzzle ^ gateway.puzzle).reset();

            connect(host, peer, info);
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
