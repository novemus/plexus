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

struct traverse
{
    enum binding
    {
        independent = 0,
        port_dependent = 1,
        address_dependent = 2,
        address_and_port_dependent = 3
    };

    struct
    {
        bool nat : 1;
        bool hairpin : 1;
        bool random_port : 1;
        bool variable_address : 1;
        binding mapping : 2;
        binding filtering : 2;
    }
    traits;

    udp::endpoint inner_endpoint;
    udp::endpoint outer_endpoint;
};

struct identity
{
    std::string owner;
    std::string pin;
};

struct cryptoid
{
    std::string certfile;
    std::string keyfile;
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

using observer = std::function<void(const identity& /* host */,
                                    const identity& /* peer */)>;

using fallback = std::function<void(const identity& /* host */,
                                    const identity& /* peer */,
                                    const std::string& /* error */)>;

LIBPLEXUS_EXPORT
void explore_network(boost::asio::io_context& io, const udp::endpoint& bind, const udp::endpoint& stun, const std::function<void(const traverse&)>& handler, const std::function<void(const std::string&)>& failure) noexcept(true);
LIBPLEXUS_EXPORT
void forward_advent(boost::asio::io_context& io, const rendezvous& mediator, const std::string& app, const std::string& repo, const identity& host, const identity& peer, const observer& handler, const fallback& failure) noexcept(true);
LIBPLEXUS_EXPORT
void receive_advent(boost::asio::io_context& io, const rendezvous& mediator, const std::string& app, const std::string& repo, const identity& host, const identity& peer, const observer& handler, const fallback& failure) noexcept(true);
LIBPLEXUS_EXPORT
void spawn_accept(boost::asio::io_context& io, const options& config, const identity& host, const identity& peer, const connector& connect, const fallback& failure = nullptr) noexcept(true);
LIBPLEXUS_EXPORT
void spawn_invite(boost::asio::io_context& io, const options& config, const identity& host, const identity& peer, const connector& connect, const fallback& failure = nullptr) noexcept(true);
LIBPLEXUS_EXPORT
void spawn_accept(boost::asio::io_context& io, const options& config, const identity& host, const identity& peer, const collector& collect, const fallback& failure = nullptr) noexcept(true);
LIBPLEXUS_EXPORT
void spawn_invite(boost::asio::io_context& io, const options& config, const identity& host, const identity& peer, const collector& collect, const fallback& failure = nullptr) noexcept(true);

}
