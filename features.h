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
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>

namespace plexus {

struct timeout_error : public std::runtime_error { timeout_error() : std::runtime_error("timeout error") {} };
struct handshake_error : public std::runtime_error { handshake_error() : std::runtime_error("handshake error") {} };
struct bad_message : public std::runtime_error { bad_message() : std::runtime_error("bad message") {} };

void exec(const std::string& prog, const std::string& args, const std::string& dir = "", const std::string& log = "");

using reference = std::pair<boost::asio::ip::udp::endpoint, /* puzzle */uint64_t>;
using abonent = std::pair</* email */std::string , /* id */std::string>;

struct mediator
{
    virtual ~mediator() {}
    virtual reference receive_request(abonent& from, abonent& whom) noexcept(false) = 0;
    virtual reference receive_response(abonent& from, abonent& whom) noexcept(false) = 0;
    virtual void dispatch_response(const abonent& from, const abonent& to, const reference& host) noexcept(false) = 0;
    virtual void dispatch_request(const abonent& from, const abonent& to, const reference& host) noexcept(false) = 0;
};

std::shared_ptr<mediator> create_email_mediator(const boost::asio::ip::tcp::endpoint& smtp,
                                                const boost::asio::ip::tcp::endpoint& imap,
                                                const std::string& login,
                                                const std::string& passwd,
                                                const std::string& cert,
                                                const std::string& key,
                                                const std::string& ca,
                                                const std::string& app_id,
                                                const std::string& cred_repo);

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
    virtual boost::asio::ip::udp::endpoint reflect_endpoint() noexcept(false) = 0;
    virtual traverse explore_network() noexcept(false) = 0;
};

std::shared_ptr<stun_client> create_stun_client(const boost::asio::ip::udp::endpoint& stun, const boost::asio::ip::udp::endpoint& bind);

struct nat_puncher : public stun_client
{
    virtual boost::asio::ip::udp::endpoint punch_hole_to_peer(const boost::asio::ip::udp::endpoint& peer, uint8_t hops) noexcept(false) = 0;
    virtual void reach_peer(const boost::asio::ip::udp::endpoint& peer, uint64_t mask) noexcept(false) = 0;
    virtual void await_peer(const boost::asio::ip::udp::endpoint& peer, uint64_t mask) noexcept(false) = 0;
};

std::shared_ptr<nat_puncher> create_nat_puncher(const boost::asio::ip::udp::endpoint& stun, const boost::asio::ip::udp::endpoint& bind);

}
