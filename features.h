/*
 * Copyright (c) 2022 Novemus Band. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 */

#pragma once

#include "plexus.h"
#include "network.h"
#include <string>
#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>

namespace plexus {

std::ostream& operator<<(std::ostream& stream, const reference& value);
std::ostream& operator<<(std::ostream& stream, const identity& value);
std::istream& operator>>(std::istream& in, reference& level);
std::istream& operator>>(std::istream& in, identity& level);

struct stun_client
{
    virtual ~stun_client() {}
    virtual network::traverse punch_hole(boost::asio::yield_context yield) noexcept(false) = 0;
};

std::shared_ptr<stun_client> create_stun_client(boost::asio::io_service& io, const udp_endpoint& stun, const boost::asio::ip::udp::endpoint& bind) noexcept(true);

struct stun_tracer : public stun_client
{
    virtual void reach_peer(boost::asio::yield_context yield, const boost::asio::ip::udp::endpoint& peer, uint64_t mask) noexcept(false) = 0;
    virtual void await_peer(boost::asio::yield_context yield, const boost::asio::ip::udp::endpoint& peer, uint64_t mask) noexcept(false) = 0;
};

std::shared_ptr<stun_tracer> create_stun_tracer(boost::asio::io_service& io, const boost::asio::ip::udp::endpoint& stun, const boost::asio::ip::udp::endpoint& bind, uint16_t punch) noexcept(true);

struct pipe
{
    virtual ~pipe() {}
    virtual const reference& pull_request(boost::asio::yield_context yield) noexcept(false) = 0;
    virtual const reference& pull_response(boost::asio::yield_context yield) noexcept(false) = 0;
    virtual void push_response(boost::asio::yield_context yield, const reference& gateway) noexcept(false) = 0;
    virtual void push_request(boost::asio::yield_context yield, const reference& gateway) noexcept(false) = 0;
    virtual const identity& host() const noexcept(true) = 0;
    virtual const identity& peer() const noexcept(true) = 0;
};

struct mediator
{
    using coroutine = std::function<void(boost::asio::yield_context yield, std::shared_ptr<pipe> pipe)>;

    virtual ~mediator() {}
    virtual void accept(const coroutine& handler) noexcept(false) = 0;
    virtual void invite(const coroutine& handler) noexcept(false) = 0;
};

std::shared_ptr<mediator> create_email_mediator(boost::asio::io_service& io,
                                                const boost::asio::ip::tcp::endpoint& smtp,
                                                const boost::asio::ip::tcp::endpoint& imap,
                                                const std::string& login,
                                                const std::string& passwd,
                                                const std::string& cert,
                                                const std::string& key,
                                                const std::string& ca,
                                                const std::string& app,
                                                const std::string& repo,
                                                const identity& host,
                                                const identity& peer) noexcept(true);
}
