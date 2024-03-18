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

#include <tubus/socket.h>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>

namespace plexus {

using udp = boost::asio::ip::udp;
using tcp = boost::asio::ip::tcp;

struct identity
{
    std::string owner;
    std::string pin;
};

struct reference
{
    udp::endpoint endpoint;
    uint64_t puzzle = 0;
};

struct mediator
{
    std::string app;
    std::string repo;
    tcp::endpoint smtp;
    tcp::endpoint imap;
    std::string login;
    std::string password;
    std::string cert;
    std::string key;
    std::string ca;
};

struct options : public mediator
{
    udp::endpoint stun;
    udp::endpoint bind;
    uint16_t hops;
};

using connector = std::function<void(const identity& /* host */,
                                     const identity& /* peer */,
                                     const udp::endpoint& /* local */,
                                     const reference& /* gateway */,
                                     const reference& /* faraway */)>;

using collector = std::function<void(const identity& /* host */,
                                     const identity& /* peer */,
                                     tubus::socket&& /* socket */)>;

using fallback = std::function<void(const identity& /* host */,
                                    const identity& /* peer */,
                                    const std::string& /* error */)>;

void spawn_accept(boost::asio::io_service& io, const options& config, const identity& host, const identity& peer, const connector& connect, const fallback& notify = nullptr) noexcept(true);
void spawn_invite(boost::asio::io_service& io, const options& config, const identity& host, const identity& peer, const connector& connect, const fallback& notify = nullptr) noexcept(true);

void spawn_accept(boost::asio::io_service& io, const options& config, const identity& host, const identity& peer, const collector& collect, const fallback& notify = nullptr) noexcept(true);
void spawn_invite(boost::asio::io_service& io, const options& config, const identity& host, const identity& peer, const collector& collect, const fallback& notify = nullptr) noexcept(true);

}
