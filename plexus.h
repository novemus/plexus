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

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>

namespace plexus {

struct timeout_error : public std::runtime_error { timeout_error() : std::runtime_error("timeout error") {} };
struct handshake_error : public std::runtime_error { handshake_error() : std::runtime_error("handshake error") {} };
struct bad_message : public std::runtime_error { bad_message() : std::runtime_error("bad message") {} };
struct bad_network : public std::runtime_error { bad_network() : std::runtime_error("bad network") {} };
struct bad_identity : public std::runtime_error { bad_identity() : std::runtime_error("bad identity") {} };

void exec(const std::string& prog, const std::string& args = "", const std::string& dir = "", const std::string& log = "", bool wait = false) noexcept(false);

using udp_endpoint = boost::asio::ip::udp::endpoint;
using tcp_endpoint = boost::asio::ip::tcp::endpoint;

struct identity
{
    std::string owner;
    std::string pin;
};

struct reference
{
    udp_endpoint endpoint;
    uint64_t puzzle = 0;
};

namespace common {

struct options
{
    std::string app;
    std::string repo;
    tcp_endpoint smtp;
    tcp_endpoint imap;
    std::string login;
    std::string password;
    std::string cert;
    std::string key;
    std::string ca;
    udp_endpoint stun;
    udp_endpoint bind;
    uint16_t hops;
};

using connector = std::function<void(const identity& /* host */,
                                     const identity& /* peer */,
                                     const udp_endpoint& /* local */,
                                     const reference& /* gateway */,
                                     const reference& /* faraway */)>;

void accept(const options& config, const identity& host, const identity& peer, const connector& handler) noexcept(false);
void invite(const options& config, const identity& host, const identity& peer, const connector& handler) noexcept(false);

}}
