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
#include <boost/asio.hpp>
#include <plexus/export.h>
#include <wormhole/wormhole.h>

namespace plexus {

using protocol = wormhole::protocol;
using schema   = wormhole::schema;
using endpoint = wormhole::endpoint;
using criteria = wormhole::criteria;

struct firewall
{
    enum relation : uint8_t
    {
        independent = 0,
        port_dependent = 1,
        address_dependent = 2,
        address_and_port_dependent = 3
    };

    bool nat : 1;
    bool hairpin : 1;
    bool random_port : 1;
    bool variable_address : 1;
    relation mapping : 2;
    relation filtering : 2;

    firewall() 
        : nat(false)
        , hairpin(false)
        , random_port(false)
        , variable_address(false)
        , mapping(relation::independent)
        , filtering(relation::independent)
    { }

    firewall(bool n, bool h, bool r, bool v, relation m, relation f) 
        : nat(n)
        , hairpin(h)
        , random_port(r)
        , variable_address(v)
        , mapping(m)
        , filtering(f)
    { }
};

struct traverse
{
    struct hole 
    {
        firewall force;
        endpoint inner;
        endpoint outer;
    };

    hole udp;
    hole tcp;
};

struct identity
{
    std::string owner;
    std::string pin;
};

struct contract
{
    endpoint inner;
    endpoint outer;
    endpoint alien;
    uint64_t secret = 0;
    criteria qos;
};

struct emailer
{
    endpoint smtp;
    endpoint imap;
    std::string login;
    std::string password;
    std::string cert; 
    std::string key;
    std::string ca;
};

struct dhtnode
{
    std::string bootstrap; // bootstrap URL
    uint16_t port = 4222;  // node port
    uint32_t network = 0;  // network id
};

using rendezvous = std::variant<emailer, dhtnode>;

struct location
{
    endpoint udp;
    endpoint tcp;
};

struct ricochet
{
    endpoint server;  // ricochet server endpoint
    std::string cert; // client cert
    std::string key;  // client key
    std::string ca;   // CA cert
};

enum checkup
{
    noneed, strict, faulty, simple
};

struct routing
{
    enum favour
    {
        direct, bridge, either
    };

    favour udp;
    favour tcp;
};

struct options
{
    std::string app;     // application id
    std::string repo;    // path to the application repository
    location bind;       // endpoints to bind the application
    location stun;       // endpoints of the stun servers
    uint16_t hops;       // ttl of the hole punching packet
    checkup mode;        // nat explore mode
    criteria qos;        // application protocol and connection strategy
    ricochet relay;      // ricochet relay service
    routing route;       // routing mode
    rendezvous mediator; // rendezvous service
};

using connector = std::function<void(const identity& /* host */,
                                     const identity& /* peer */,
                                     const contract& /* info */)>;

using observer = std::function<void(const identity& /* host */,
                                    const identity& /* peer */)>;

using fallback = std::function<void(const identity& /* host */,
                                    const identity& /* peer */,
                                    const std::string& /* error */)>;

LIBPLEXUS_EXPORT
void explore_network(boost::asio::io_context& io, const location& bind, const location& stun, checkup mode, const std::function<void(const traverse&)>& handler, const std::function<void(const std::string&)>& failure) noexcept(true);
LIBPLEXUS_EXPORT
void forward_advent(boost::asio::io_context& io, const rendezvous& mediator, const std::string& app, const std::string& repo, const identity& host, const identity& peer, const observer& handler, const fallback& failure) noexcept(true);
LIBPLEXUS_EXPORT
void receive_advent(boost::asio::io_context& io, const rendezvous& mediator, const std::string& app, const std::string& repo, const identity& host, const identity& peer, const observer& handler, const fallback& failure) noexcept(true);
LIBPLEXUS_EXPORT
void spawn_accept(boost::asio::io_context& io, const options& config, const identity& host, const identity& peer, const connector& connect, const fallback& failure = nullptr) noexcept(true);
LIBPLEXUS_EXPORT
void spawn_invite(boost::asio::io_context& io, const options& config, const identity& host, const identity& peer, const connector& connect, const fallback& failure = nullptr) noexcept(true);

LIBPLEXUS_EXPORT std::ostream& operator<<(std::ostream& out, const identity& val) noexcept(false);
LIBPLEXUS_EXPORT std::istream& operator>>(std::istream& in, identity& val) noexcept(false);
LIBPLEXUS_EXPORT std::ostream& operator<<(std::ostream& out, const firewall& val) noexcept(false);
LIBPLEXUS_EXPORT std::istream& operator>>(std::istream& in, firewall& val) noexcept(false);
LIBPLEXUS_EXPORT std::ostream& operator<<(std::ostream& out, const routing::favour& val) noexcept(false);
LIBPLEXUS_EXPORT std::istream& operator>>(std::istream& in, routing::favour& val) noexcept(false);
LIBPLEXUS_EXPORT std::ostream& operator<<(std::ostream& out, const checkup& val) noexcept(false);
LIBPLEXUS_EXPORT std::istream& operator>>(std::istream& in, checkup& val) noexcept(false);
}
