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
#include "features.h"
#include "utils.h"
#include <logger.h>

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

namespace common {

void accept(const options& config, const identity& host, const identity& peer, const connector& handler) noexcept(false)
{
    boost::asio::io_service io;
    auto mediator = plexus::create_email_mediator(io, config.smtp, config.imap, config.login, config.password, config.cert, config.key, config.ca, config.app, config.repo, host, peer);

    mediator->accept([&](boost::asio::yield_context yield, std::shared_ptr<plexus::pipe> pipe)
    {
        auto tracer = plexus::create_stun_tracer(io, config.stun, config.bind, config.hops);

        auto hole = tracer->punch_hole(yield);
        if (hole.traits.mapping != network::traverse::independent)
            throw plexus::bad_network();

        reference faraway = pipe->pull_request(yield);
        reference gateway = { hole.outer_endpoint, plexus::utils::random<uint64_t>() };
        pipe->push_response(yield, gateway);

        tracer->await_peer(yield, faraway.endpoint, faraway.puzzle ^ gateway.puzzle);

        handler(pipe->host(), pipe->peer(), hole.inner_endpoint, gateway, faraway);
    });

    io.run();
}

void invite(const options& config, const identity& host, const identity& peer, const connector& handler) noexcept(false)
{
    boost::asio::io_service io;
    auto mediator = plexus::create_email_mediator(io, config.smtp, config.imap, config.login, config.password, config.cert, config.key, config.ca, config.app, config.repo, host, peer);

    mediator->invite([&](boost::asio::yield_context yield, std::shared_ptr<plexus::pipe> pipe)
    {
        auto tracer = plexus::create_stun_tracer(io, config.stun, config.bind, config.hops);

        auto hole = tracer->punch_hole(yield);
        if (hole.traits.mapping != network::traverse::independent)
            throw plexus::bad_network();

        plexus::reference gateway = { hole.outer_endpoint, plexus::utils::random<uint64_t>() };
        pipe->push_request(yield, gateway);
        plexus::reference faraway = pipe->pull_response(yield);

        tracer->reach_peer(yield, faraway.endpoint, faraway.puzzle ^ gateway.puzzle);

        handler(pipe->host(), pipe->peer(), hole.inner_endpoint, gateway, faraway);
    });

    io.run();
}

}}
