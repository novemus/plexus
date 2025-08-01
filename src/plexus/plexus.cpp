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

namespace plexus {

std::ostream& operator<<(std::ostream& stream, const reference& value)
{
    if (stream.rdbuf())
        return stream << value.endpoint << "/" << value.puzzle;
    return stream;
}

std::ostream& operator<<(std::ostream& stream, const identity& value)
{
    if (stream.rdbuf())
        return stream << value.owner << "/" << value.pin;
    return stream;
}

std::istream& operator>>(std::istream& in, reference& value)
{
    std::string str;
    in >> str;

    std::smatch match;
    if (std::regex_match(str, match, std::regex("^([^/]+)/([^/]+)$")))
    {
        value.endpoint = plexus::utils::parse_endpoint<boost::asio::ip::udp::endpoint>(match[1].str(), "");
        value.puzzle = boost::lexical_cast<uint64_t>(match[2].str());
        return in;
    }

    throw boost::bad_lexical_cast();
}

std::istream& operator>>(std::istream& in, identity& value)
{
    std::string str;
    in >> str;

    std::smatch match;
    if (std::regex_match(str, match, std::regex("^([^/]*)/([^/]*)$")))
    {
        value.owner = match[1].str();
        value.pin = match[2].str();
        return in;
    }

    throw boost::bad_lexical_cast();
}

void explore_network(boost::asio::io_context& io, const udp::endpoint& bind, const udp::endpoint& stun, const std::function<void(const traverse&)>& handler, const std::function<void(const std::string&)>& failure) noexcept(true)
{
    boost::asio::spawn(io, [&io, bind, stun, handler, failure](boost::asio::yield_context yield)
    {
        _inf_ << "exploring network by stun " << stun << " from " << bind;

        try
        {
            auto client = plexus::create_stun_client(io, stun, bind);
            auto hole = client->punch_hole(yield);

            handler(hole);
        }
        catch (const std::exception& e)
        {
            _err_ << "exploring network by stun " << stun << " from " << bind << " failed: " << e.what();

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

        _inf_ << "accepting " << peer << " by " << host << " for " << config.app;

        try
        {
            auto binder = plexus::create_stun_binder(io, config.stun, config.bind, config.hops);

            auto hole = binder->punch_hole(yield);
            if (hole.traits.mapping != traverse::independent)
                throw plexus::context_error(__FUNCTION__, "bad network");

            reference faraway = pipe->pull_request(yield);
            reference gateway = {hole.outer_endpoint, plexus::utils::random<uint64_t>()};
            pipe->push_response(yield, gateway);

            binder->await_peer(yield, faraway.endpoint, faraway.puzzle ^ gateway.puzzle);

            connect(host, peer, hole.inner_endpoint, gateway, faraway);
        }
        catch (const std::exception& e)
        {
            _err_ << "accepting " << peer << " by " << host << " for " << config.app << " failed: " << e.what();

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

        _inf_ << "inviting " << peer << " by " << host << " for " << config.app;

        try
        {
            auto binder = plexus::create_stun_binder(io, config.stun, config.bind, config.hops);

            auto hole = binder->punch_hole(yield);
            if (hole.traits.mapping != traverse::independent)
                throw plexus::context_error(__FUNCTION__, "bad network");

            plexus::reference gateway = { hole.outer_endpoint, plexus::utils::random<uint64_t>() };
            pipe->push_request(yield, gateway);
            plexus::reference faraway = pipe->pull_response(yield);

            binder->reach_peer(yield, faraway.endpoint, faraway.puzzle ^ gateway.puzzle);

            connect(host, peer, hole.inner_endpoint, gateway, faraway);
        }
        catch (const std::exception& e)
        {
            _err_ << "inviting " << peer << " by " << host << " for " << config.app << " failed: " << e.what();

            if (failure)
                failure(pipe->host(), pipe->peer(), e.what());
        }
    };

    config.mediator.index() == 0
        ? spawn_invite(io, context<emailer>(config.app, config.repo, std::get<emailer>(config.mediator)), host, peer, handler)
        : spawn_invite(io, context<dhtnode>(config.app, config.repo, std::get<dhtnode>(config.mediator)), host, peer, handler);
}

void spawn_accept(boost::asio::io_context& io, const options& config, const identity& host, const identity& peer, const collector& collect, const fallback& failure) noexcept(true)
{
    spawn_accept(io, config, host, peer, [&io, collect, failure](const identity& host, const identity& peer, const udp::endpoint& bind, const reference& gateway, const reference& faraway)
    {
        _inf_ << "accepting from " << faraway.endpoint << " on " << bind;

        auto socket = std::make_shared<tubus::socket>(io, faraway.puzzle ^ gateway.puzzle);
        boost::system::error_code ec;
        socket->open(bind, ec);

        if (ec)
        {
            _err_ << "can't open " << bind << " socket: " << ec.message();

            if (failure)
                failure(host, peer, ec.message());
            return;
        }

        socket->async_accept(faraway.endpoint, [socket, faraway, host, peer, collect, failure](const boost::system::error_code& ec)
        {
            if (ec)
            {
                _err_ << "accepting from " << faraway.endpoint << " failed: " << ec.message();
                
                if (failure)
                    failure(host, peer, ec.message());
                return;
            }

            collect(host, peer, std::move(*socket));
        });
    }, failure);
}

void spawn_invite(boost::asio::io_context& io, const options& config, const identity& host, const identity& peer, const collector& collect, const fallback& failure) noexcept(true)
{
    spawn_invite(io, config, host, peer, [&io, collect, failure](const identity& host, const identity& peer, const udp::endpoint& bind, const reference& gateway, const reference& faraway)
    {
        _inf_ << "connecting to " << faraway.endpoint << " from " << bind;

        auto socket = std::make_shared<tubus::socket>(io, faraway.puzzle ^ gateway.puzzle);
        boost::system::error_code ec;
        socket->open(bind, ec);

        if (ec)
        {
            _err_ << "can't open " << bind << " socket: " << ec.message();

            if (failure)
                failure(host, peer, ec.message());
            return;
        }

        socket->async_connect(faraway.endpoint, [socket, faraway, host, peer, collect, failure](const boost::system::error_code& ec)
        {
            if (ec)
            {
                _err_ << "connecting to " << faraway.endpoint << " failed: " << ec.message();

                if (failure)
                    failure(host, peer, ec.message());
                return;
            }

            collect(host, peer, std::move(*socket));
        });
    }, failure);
}

void forward_advent(boost::asio::io_context& io, const rendezvous& mediator, const std::string& app, const std::string& repo, const identity& host, const identity& peer, const observer& handler, const fallback& failure) noexcept(true)
{
    _inf_ << "forwarding advent from " << host << " for " << peer;

    mediator.index() == 0
        ? forward_advent(io, context<emailer>(app, repo, std::get<emailer>(mediator)), host, peer, handler, failure)
        : forward_advent(io, context<dhtnode>(app, repo, std::get<dhtnode>(mediator)), host, peer, handler, failure);
}

void receive_advent(boost::asio::io_context& io, const rendezvous& mediator, const std::string& app, const std::string& repo, const identity& host, const identity& peer, const observer& handler, const fallback& failure) noexcept(true)
{
    _inf_ << "receiving advent from " << peer << " for " << host;

    mediator.index() == 0
        ? receive_advent(io, context<emailer>(app, repo, std::get<emailer>(mediator)), host, peer, handler, failure)
        : receive_advent(io, context<dhtnode>(app, repo, std::get<dhtnode>(mediator)), host, peer, handler, failure);
}

}
