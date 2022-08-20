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
#include <vector>
#include <boost/asio/ip/icmp.hpp>
#include <boost/asio/ip/udp.hpp>
#include "raw.h"

namespace plexus { namespace network {

struct ssl
{
    virtual ~ssl() {}
    virtual void connect() noexcept(false) = 0;
    virtual void shutdown() noexcept(true) = 0;
    virtual size_t read(uint8_t* buffer, size_t len) noexcept(false) = 0;
    virtual size_t write(const uint8_t* buffer, size_t len) noexcept(false) = 0;
};

std::shared_ptr<ssl> create_ssl_client(const endpoint& remote, const std::string& cert = "", const std::string& key = "", const std::string& ca = "");

struct transport
{
    struct transfer
    {
        endpoint remote;
        std::shared_ptr<buffer> packet; // ip_packet on receive or icmp_packet|tcp_packet|udp_packet|... on send

        transfer(size_t buf) : packet(std::make_shared<buffer>(buf)) {}
        transfer(std::shared_ptr<buffer> buf) : packet(buf) {}
        transfer(const endpoint& ep) : remote(ep) {}
        transfer(const endpoint& ep, std::shared_ptr<buffer> buf) : remote(ep), packet(buf) {}
    };

    virtual ~transport() {}
    virtual void send(std::shared_ptr<transfer> tran, int64_t timeout_ms = 1600, uint8_t hops = 64) noexcept(false) = 0;
    virtual void receive(std::shared_ptr<transfer> tran, int64_t timeout_ms = 1600) noexcept(false) = 0;
};

std::shared_ptr<transport> create_udp_transport(const endpoint& local);
std::shared_ptr<transport> create_tcp_transport(const endpoint& local);
std::shared_ptr<transport> create_icmp_transport(const endpoint& local);

}}
