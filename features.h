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

struct timeout_error : public std::runtime_error { timeout_error() : std::runtime_error("timeout error") {} };
struct handshake_error : public std::runtime_error { handshake_error() : std::runtime_error("handshake error") {} };
struct bad_message : public std::runtime_error { bad_message() : std::runtime_error("bad message") {} };
struct bad_network : public std::runtime_error { bad_network() : std::runtime_error("bad network") {} };
struct bad_identity : public std::runtime_error { bad_identity() : std::runtime_error("bad identity") {} };

void exec(const std::string& prog, const std::string& args = "", const std::string& dir = "", const std::string& log = "", bool wait = false) noexcept(false);

std::ostream& operator<<(std::ostream& stream, const reference& value);
std::ostream& operator<<(std::ostream& stream, const identity& value);
std::istream& operator>>(std::istream& in, reference& level);
std::istream& operator>>(std::istream& in, identity& level);

struct stun_client
{
    virtual ~stun_client() {}
    virtual network::traverse punch_hole(boost::asio::yield_context yield) noexcept(false) = 0;
};

std::shared_ptr<stun_client> create_stun_client(boost::asio::io_service& io, const boost::asio::ip::udp::endpoint& stun, const boost::asio::ip::udp::endpoint& bind) noexcept(true);

struct stun_binder : public stun_client
{
    virtual void reach_peer(boost::asio::yield_context yield, const boost::asio::ip::udp::endpoint& peer, uint64_t mask) noexcept(false) = 0;
    virtual void await_peer(boost::asio::yield_context yield, const boost::asio::ip::udp::endpoint& peer, uint64_t mask) noexcept(false) = 0;
};

std::shared_ptr<stun_binder> create_stun_binder(boost::asio::io_service& io, const boost::asio::ip::udp::endpoint& stun, const boost::asio::ip::udp::endpoint& bind, uint16_t punch) noexcept(true);

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

using coroutine = std::function<void(boost::asio::yield_context yield, std::shared_ptr<pipe> pipe)>;

void spawn_accept(boost::asio::io_service& io, const mediator& conf, const identity& host, const identity& peer, const coroutine& handler) noexcept(true);
void spawn_invite(boost::asio::io_service& io, const mediator& conf, const identity& host, const identity& peer, const coroutine& handler) noexcept(true);

}
