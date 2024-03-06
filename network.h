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

#include "socket.h"
#include <string>
#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ssl.hpp>

namespace plexus { namespace network {

constexpr int64_t default_tcp_timeout_ms = 10000;
constexpr int64_t default_udp_timeout_ms = 1600;

using tcp_socket = asio_socket<boost::asio::ip::tcp::socket, boost::asio::ip::tcp::endpoint, default_tcp_timeout_ms>;
using ssl_socket = asio_socket<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>, boost::asio::ip::tcp::endpoint, default_tcp_timeout_ms>;
using udp_socket = asio_socket<boost::asio::ip::udp::socket, boost::asio::ip::udp::endpoint, default_udp_timeout_ms>;

std::shared_ptr<ssl_socket> create_ssl_client(boost::asio::io_service& io, const boost::asio::ip::tcp::endpoint& remote, const std::string& cert = "", const std::string& key = "", const std::string& ca = "");
std::shared_ptr<tcp_socket> create_tcp_client(boost::asio::io_service& io, const boost::asio::ip::tcp::endpoint& remote, const boost::asio::ip::tcp::endpoint& local, uint8_t hops = 128);
std::shared_ptr<udp_socket> create_udp_transport(boost::asio::io_service& io, const boost::asio::ip::udp::endpoint& local = boost::asio::ip::udp::endpoint());

}}
