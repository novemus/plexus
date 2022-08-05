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
#include "network.h"

namespace plexus {

struct timeout_error : public std::runtime_error { timeout_error() : std::runtime_error("timeout error") {} };
struct handshake_error : public std::runtime_error { handshake_error() : std::runtime_error("handshake error") {} };

void exec(const std::string& prog, const std::string& args, const std::string& dir = "", const std::string& log = "");

struct mediator
{
    virtual ~mediator() {}
    virtual plexus::network::endpoint receive_request() noexcept(false) = 0;
    virtual plexus::network::endpoint receive_response() noexcept(false) = 0;
    virtual void dispatch_response(const plexus::network::endpoint& hole) noexcept(false) = 0;
    virtual void dispatch_request(const plexus::network::endpoint& hole) noexcept(false) = 0;
};

std::shared_ptr<mediator> create_email_mediator(const std::string& host_id,
                                                const std::string& peer_id,
                                                const std::string& smtp,
                                                const std::string& imap,
                                                const std::string& login,
                                                const std::string& passwd,
                                                const std::string& from,
                                                const std::string& to,
                                                const std::string& cert = "",
                                                const std::string& key = "",
                                                const std::string& ca = "",
                                                const std::string& smime_peer = "",
                                                const std::string& smime_cert = "",
                                                const std::string& smime_key = "",
                                                const std::string& smime_ca = "");

const uint16_t DEFAULT_STUN_PORT = 3478u;

enum binding
{
    unknown = 0,
    independent = 1,
    address_dependent = 2,
    address_and_port_dependent = 3
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

using namespace network;

struct puncher
{
    virtual ~puncher() {}
    virtual traverse explore_network() noexcept(false) = 0;
    virtual endpoint punch_udp_hole() noexcept(false) = 0;
    virtual endpoint punch_udp_hole_to_peer(const endpoint& peer, uint8_t hops) noexcept(false) = 0;
    virtual void reach_peer(const endpoint& peer) noexcept(false) = 0;
    virtual void await_peer(const endpoint& peer) noexcept(false) = 0;
};

std::shared_ptr<puncher> create_stun_puncher(const endpoint& stun, const endpoint& local);

}
