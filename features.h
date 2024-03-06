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

void exec(const std::string& prog, const std::string& args = "", const std::string& dir = "", const std::string& log = "", bool wait = false);

enum binding
{
    address_and_port_dependent = 0,
    address_dependent = 1,
    port_dependent = 2,
    independent = 3
};

struct traverse
{
    unsigned int nat : 1,
                 hairpin : 1,
                 random_port : 1,
                 variable_address : 1,
                 mapping : 2, // enum binding
                 filtering : 2; // enum binding
};

struct stun_client
{
    virtual ~stun_client() {}
    virtual boost::asio::ip::udp::endpoint reflect_endpoint(boost::asio::yield_context yield) noexcept(false) = 0;
    virtual traverse explore_network(boost::asio::yield_context yield) noexcept(false) = 0;
};

std::shared_ptr<stun_client> create_stun_client(boost::asio::io_service& io, const boost::asio::ip::udp::endpoint& server, const boost::asio::ip::udp::endpoint& local);

struct nat_puncher : public stun_client
{
    virtual boost::asio::ip::udp::endpoint punch_hole_to_peer(boost::asio::yield_context yield, const boost::asio::ip::udp::endpoint& peer, uint8_t hops) noexcept(false) = 0;
    virtual void reach_peer(boost::asio::yield_context yield, const boost::asio::ip::udp::endpoint& peer, uint64_t mask) noexcept(false) = 0;
    virtual void await_peer(boost::asio::yield_context yield, const boost::asio::ip::udp::endpoint& peer, uint64_t mask) noexcept(false) = 0;
};

std::shared_ptr<nat_puncher> create_nat_puncher(boost::asio::io_service& io, const boost::asio::ip::udp::endpoint& stun, boost::asio::ip::udp::endpoint& bind);

struct reference
{
    boost::asio::ip::udp::endpoint endpoint;
    uint64_t puzzle = 0;
};

struct identity
{
    std::string owner;
    std::string pin;
};

std::ostream& operator<<(std::ostream& stream, const reference& value);
std::ostream& operator<<(std::ostream& stream, const identity& value);
std::istream& operator>>(std::istream& in, reference& level);
std::istream& operator>>(std::istream& in, identity& level);

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

using plexus_coro = std::function<void(boost::asio::io_service& io, boost::asio::yield_context yield, std::shared_ptr<pipe> pipe)>;

struct mediator
{
    virtual ~mediator() {}
    virtual void accept(const plexus_coro& handler) noexcept(false) = 0;
    virtual void invite(const plexus_coro& handler) noexcept(false) = 0;
};

std::shared_ptr<mediator> create_email_mediator(const boost::asio::ip::tcp::endpoint& smtp,
                                                const boost::asio::ip::tcp::endpoint& imap,
                                                const std::string& login,
                                                const std::string& passwd,
                                                const std::string& cert,
                                                const std::string& key,
                                                const std::string& ca,
                                                const std::string& app,
                                                const std::string& repo,
                                                const identity& host,
                                                const identity& peer);
}
