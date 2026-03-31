/*
 * Copyright (c) 2022 Novemus Band. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 */

#include <plexus/network.h>
#include <boost/asio/ssl.hpp>

namespace plexus { namespace network {

class ssl_socket_impl : public ssl_socket
{
    boost::asio::ssl::context m_ssl;

public:

    ssl_socket_impl(const boost::asio::ip::tcp::endpoint& local, const boost::asio::ip::tcp::endpoint& remote, boost::asio::io_context& io, boost::asio::ssl::context&& ssl)
        : ssl_socket(local, remote, io, ssl)
        , m_ssl(std::move(ssl))
    {
        ssl_socket::lowest_layer().set_option(boost::asio::socket_base::keep_alive(true));
    }
};

std::shared_ptr<tcp_socket> create_tcp_socket(boost::asio::io_context& io, const boost::asio::ip::tcp::endpoint& local, const boost::asio::ip::tcp::endpoint& remote)
{
    auto socket = std::make_shared<tcp_socket>(local, remote, io);
    socket->set_option(boost::asio::socket_base::keep_alive(true));
    return socket;
}

std::shared_ptr<ssl_socket> create_ssl_socket(boost::asio::io_context& io, const boost::asio::ip::tcp::endpoint& local, const boost::asio::ip::tcp::endpoint& remote, bool client, const std::string& cert, const std::string& key, const std::string& ca)
{
    boost::asio::ssl::context ssl = boost::asio::ssl::context(boost::asio::ssl::context::sslv23);

    ssl.set_options(boost::asio::ssl::context::default_workarounds | (client ? boost::asio::ssl::context::sslv23_client : boost::asio::ssl::context::sslv23_server));
    if (!cert.empty() && !key.empty())
    {
        ssl.use_certificate_file(cert, boost::asio::ssl::context::pem);
        ssl.use_private_key_file(key, boost::asio::ssl::context::pem);
    }

    if (!ca.empty())
    {
        ssl.set_verify_mode(boost::asio::ssl::verify_peer | boost::asio::ssl::verify_fail_if_no_peer_cert | boost::asio::ssl::verify_client_once );
        ssl.load_verify_file(ca);
    }

    return std::make_shared<ssl_socket_impl>(local, remote, io, std::move(ssl));
}

}}
