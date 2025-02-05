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

#include <variant>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <plexus/export.h>
#include <tubus/socket.h>

namespace plexus {

using namespace boost::asio::ip;

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

struct emailer
{
    tcp::endpoint smtp;
    tcp::endpoint imap;
    std::string login;
    std::string password;
    std::string cert; 
    std::string key;
    std::string ca;
};

struct dhtnode
{
    std::string bootstrap; // bootstrap URL
    uint16_t port = 4222; // node port
    uint32_t network = 0; // network id
};

using rendezvous = std::variant<emailer, dhtnode>;

struct options
{
    std::string app; // application id
    std::string repo; // path to application repository
    udp::endpoint stun; // endpoint of public stun server
    udp::endpoint bind; // local endpoint to bind the application
    uint16_t hops; // ttl of the udp-hole punching packet
    rendezvous mediator; // signaling service to trigger peer connections
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

LIBPLEXUS_EXPORT
void spawn_accept(boost::asio::io_service& io, const options& config, const identity& host, const identity& peer, const connector& connect, const fallback& notify = nullptr) noexcept(true);
LIBPLEXUS_EXPORT
void spawn_invite(boost::asio::io_service& io, const options& config, const identity& host, const identity& peer, const connector& connect, const fallback& notify = nullptr) noexcept(true);
LIBPLEXUS_EXPORT
void spawn_accept(boost::asio::io_service& io, const options& config, const identity& host, const identity& peer, const collector& collect, const fallback& notify = nullptr) noexcept(true);
LIBPLEXUS_EXPORT
void spawn_invite(boost::asio::io_service& io, const options& config, const identity& host, const identity& peer, const collector& collect, const fallback& notify = nullptr) noexcept(true);

}
