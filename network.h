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
#include "icmp.h"

namespace plexus { namespace network {

struct ssl
{
    virtual ~ssl() {}
    virtual void connect() noexcept(false) = 0;
    virtual void shutdown() noexcept(true) = 0;
    virtual size_t read(uint8_t* buffer, size_t len) noexcept(false) = 0;
    virtual size_t write(const uint8_t* buffer, size_t len) noexcept(false) = 0;
};

std::shared_ptr<ssl> create_ssl_client(const endpoint& remote, const std::string& cert = "", const std::string& key = "", const std::string& ca = "", int64_t timeout_sec = 10);

struct udp
{
    struct transfer
    {
        endpoint remote;
        std::vector<uint8_t> buffer;

        transfer(size_t b) : buffer(b, 0) {}
        transfer(const endpoint& r, size_t b = 0) : remote(r), buffer(b, 0) {}
        transfer(const endpoint& r, const std::vector<uint8_t>& b) : remote(r), buffer(b) {}
        transfer(const endpoint& r, std::initializer_list<uint8_t> b) : remote(r), buffer(b) {}
    };

    virtual ~udp() {}
    virtual size_t send(std::shared_ptr<transfer> tran, int64_t timeout_ms = 1600, uint8_t hops = 64) noexcept(false) = 0;
    virtual size_t receive(std::shared_ptr<transfer> tran, int64_t timeout_ms = 1600) noexcept(false) = 0;
};

std::shared_ptr<udp> create_udp_channel(const endpoint& local);

struct icmp
{
    struct transfer
    {
        address remote;
        std::shared_ptr<buffer> packet; // ip_packet on receive or icmp_packet on send

        transfer(const address& ip, std::shared_ptr<buffer> pack) : remote(ip), packet(pack) {}
        transfer(std::shared_ptr<buffer> pack) : packet(pack) {}
    };

    virtual ~icmp() {}
    virtual void send(std::shared_ptr<transfer> tran, int64_t timeout_ms = 1600, uint8_t hops = 64) noexcept(false) = 0;
    virtual void receive(std::shared_ptr<transfer> tran, int64_t timeout_ms = 1600) noexcept(false) = 0;
};

std::shared_ptr<icmp> create_icmp_channel(const address& local = "");

}}
