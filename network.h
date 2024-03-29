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

#include <tubus/buffer.h>
#include <string>
#include <vector>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>

namespace plexus { namespace network {

struct tcp
{
    virtual ~tcp() {}
    virtual void connect() noexcept(false) = 0;
    virtual void shutdown() noexcept(true) = 0;
    virtual size_t read(uint8_t* buffer, size_t len, bool deferred = false) noexcept(false) = 0;
    virtual size_t write(const uint8_t* buffer, size_t len, bool deferred = false) noexcept(false) = 0;
};

std::shared_ptr<tcp> create_ssl_client(const boost::asio::ip::tcp::endpoint& remote, const std::string& cert = "", const std::string& key = "", const std::string& ca = "");
std::shared_ptr<tcp> create_tcp_client(const boost::asio::ip::tcp::endpoint& remote, const boost::asio::ip::tcp::endpoint& local, int64_t timeout_ms = 10000, uint8_t hops = 64);

struct udp
{
    virtual ~udp() {}
    virtual size_t send(const boost::asio::ip::udp::endpoint& remote, const tubus::const_buffer& buffer, int64_t timeout_ms = 1600, uint8_t hops = 64) noexcept(false) = 0;
    virtual size_t receive(const boost::asio::ip::udp::endpoint& remote, const tubus::mutable_buffer& buffer, int64_t timeout_ms = 1600) noexcept(false) = 0;
};

std::shared_ptr<udp> create_udp_transport(const boost::asio::ip::udp::endpoint& local = boost::asio::ip::udp::endpoint());

}}
