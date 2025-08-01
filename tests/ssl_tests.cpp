/*
 * Copyright (c) 2022 Novemus Band. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 */

#include <cstdlib>
#include <stdio.h>
#include <string.h>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/test/unit_test.hpp>
#include <plexus/network.h>

namespace {

class ssl_echo_session : public std::enable_shared_from_this<ssl_echo_session>
{
    enum { max_length = 1024 };

    char m_data[max_length];
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> m_socket;

public:

    ssl_echo_session(boost::asio::io_context& io, boost::asio::ssl::context &ssl)
        : m_socket(io, ssl)
    {
    }

    boost::asio::ssl::stream<boost::asio::ip::tcp::socket>::lowest_layer_type &socket()
    {
        return m_socket.lowest_layer();
    }

    void start()
    {
        m_socket.async_handshake(
            boost::asio::ssl::stream_base::server,
            boost::bind(&ssl_echo_session::handle_handshake, shared_from_this(), boost::asio::placeholders::error)
            );
    }

protected:

    void handle_handshake(const boost::system::error_code &error)
    {
        if (!error)
        {
            m_socket.async_read_some(
                boost::asio::buffer(m_data, max_length),
                boost::bind(&ssl_echo_session::handle_read, shared_from_this(), boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred)
                );
        }
    }

    void handle_read(const boost::system::error_code &error, size_t transferred)
    {
        if (!error)
        {
            m_socket.async_write_some(
                boost::asio::buffer(m_data, transferred),
                boost::bind(&ssl_echo_session::handle_write, shared_from_this(), boost::asio::placeholders::error)
                );
        }
    }

    void handle_write(const boost::system::error_code &error)
    {
        if (!error)
        {
            m_socket.async_read_some(
                boost::asio::buffer(m_data, max_length),
                boost::bind(&ssl_echo_session::handle_read, shared_from_this(), boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred)
                );
        }
    }
};

class ssl_echo_server
{
    boost::asio::io_context& m_io;
    boost::asio::ip::tcp::acceptor m_acceptor;
    boost::asio::ssl::context m_ssl;

public:

    ssl_echo_server(boost::asio::io_context& io, unsigned short port, const std::string& cert, const std::string& key, const std::string& ca = "")
        : m_io(io)
        , m_acceptor(m_io, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port))
        , m_ssl(boost::asio::ssl::context::sslv23)
    {
        m_ssl.set_options(boost::asio::ssl::context::default_workarounds| boost::asio::ssl::context::sslv23_server);
        m_ssl.use_certificate_file(cert, boost::asio::ssl::context::pem);
        m_ssl.use_private_key_file(key, boost::asio::ssl::context::pem);
        if (!ca.empty())
        {
            m_ssl.set_verify_mode(boost::asio::ssl::verify_peer | boost::asio::ssl::verify_fail_if_no_peer_cert | boost::asio::ssl::verify_client_once);
            m_ssl.load_verify_file(ca);
        }

        boost::asio::post(m_io, boost::bind(&ssl_echo_server::start_accept, this));
    }

protected:

    void start_accept()
    {
        auto session = std::make_shared<ssl_echo_session>(m_io, m_ssl);
        m_acceptor.async_accept(
            session->socket(),
            boost::bind(&ssl_echo_server::handle_accept, this, session, boost::asio::placeholders::error)
            );
    }

    void handle_accept(std::shared_ptr<ssl_echo_session> session, const boost::system::error_code &error)
    {
        if (!error)
            session->start();

        start_accept();
    }
};

std::shared_ptr<ssl_echo_server> create_ssl_server(boost::asio::io_context& io, unsigned short port, const std::string& cert = "", const std::string& key = "", const std::string& ca = "")
{
    return std::make_shared<ssl_echo_server>(io, port, cert, key, ca);
}

const uint16_t SSL_PORT = 4433;
const boost::asio::ip::tcp::endpoint SSL_SERVER(boost::asio::ip::make_address("127.0.0.1"), SSL_PORT);
const boost::asio::ip::tcp::endpoint WRONG_SSL_SERVER(boost::asio::ip::make_address("1.2.3.4"), SSL_PORT);

}

BOOST_AUTO_TEST_CASE(no_check_certs)
{
    boost::asio::io_context io;
    auto server = create_ssl_server(io, SSL_PORT, "./certs/server.crt", "./certs/server.key");

    boost::asio::spawn(io, [&](boost::asio::yield_context yield)
    {
        auto client = plexus::network::create_ssl_client(io, SSL_SERVER);
        BOOST_REQUIRE_NO_THROW(client->connect(yield));
        BOOST_REQUIRE_NO_THROW(client->handshake(boost::asio::ssl::stream_base::client, yield));

        std::string wb = "hello";
        std::string rb;

        rb.resize(wb.size());

        BOOST_CHECK_EQUAL(client->write(boost::asio::buffer(wb), yield), wb.size());
        BOOST_CHECK_EQUAL(client->read(boost::asio::buffer(rb), yield), rb.size());
        BOOST_CHECK_EQUAL(wb, rb);

        wb = "bye bye";
        rb.resize(wb.size());

        BOOST_CHECK_EQUAL(client->write(boost::asio::buffer(wb), yield), wb.size());
        BOOST_CHECK_EQUAL(client->read(boost::asio::buffer(rb), yield), rb.size());
        BOOST_CHECK_EQUAL(wb, rb);

        BOOST_REQUIRE_NO_THROW(client->shutdown());

        io.stop();
    }, boost::asio::detached);

    io.run();
}

BOOST_AUTO_TEST_CASE(check_certs)
{
    boost::asio::io_context io;
    auto server = create_ssl_server(io, SSL_PORT, "./certs/server.crt", "./certs/server.key", "./certs/ca.crt");
    
    boost::asio::spawn(io, [&](boost::asio::yield_context yield)
    {
        auto client = plexus::network::create_ssl_client(io, SSL_SERVER, "./certs/client.crt", "./certs/client.key", "./certs/ca.crt");
        BOOST_REQUIRE_NO_THROW(client->connect(yield));
        BOOST_REQUIRE_NO_THROW(client->handshake(boost::asio::ssl::stream_base::client, yield));

        std::string wb = "hello";
        std::string rb;

        rb.resize(wb.size());

        BOOST_CHECK_EQUAL(client->write(boost::asio::buffer(wb), yield), wb.size());
        BOOST_CHECK_EQUAL(client->read(boost::asio::buffer(rb), yield), rb.size());
        BOOST_CHECK_EQUAL(wb, rb);

        wb = "bye bye";
        rb.resize(wb.size());

        BOOST_CHECK_EQUAL(client->write(boost::asio::buffer(wb), yield), wb.size());
        BOOST_CHECK_EQUAL(client->read(boost::asio::buffer(rb), yield), rb.size());
        BOOST_CHECK_EQUAL(wb, rb);

        BOOST_REQUIRE_NO_THROW(client->shutdown());

        io.stop();
    }, boost::asio::detached);

    io.run();
}

BOOST_AUTO_TEST_CASE(wrong_certs)
{
    boost::asio::io_context io;
    auto server = create_ssl_server(io, SSL_PORT, "./certs/server.crt", "./certs/server.key", "./certs/ca.crt");
    
    boost::asio::spawn(io, [&](boost::asio::yield_context yield)
    {
        auto failed = plexus::network::create_ssl_client(io, WRONG_SSL_SERVER);
        BOOST_REQUIRE_THROW(failed->connect(yield, 2000), boost::system::system_error);

        auto client = plexus::network::create_ssl_client(io, SSL_SERVER, "./certs/client.crt", "./certs/client.key", "./certs/ca.crt");
        BOOST_REQUIRE_NO_THROW(client->connect(yield));
        BOOST_REQUIRE_NO_THROW(client->handshake(boost::asio::ssl::stream_base::client, yield));

        char rb;
        BOOST_REQUIRE_THROW(client->read(boost::asio::buffer(&rb, 1), yield, 2000), boost::system::system_error);

        BOOST_REQUIRE_NO_THROW(client->shutdown());

        client = plexus::network::create_ssl_client(io, SSL_SERVER, "./certs/alien/client.crt", "./certs/alien/client.key", "./certs/alien/ca.crt");
        BOOST_REQUIRE_NO_THROW(client->connect(yield));
        BOOST_REQUIRE_THROW(client->handshake(boost::asio::ssl::stream_base::client, yield), boost::system::system_error);

        BOOST_REQUIRE_NO_THROW(client->shutdown());

        io.stop();
    }, boost::asio::detached);

    io.run();
}
