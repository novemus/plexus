/*
 * Copyright (c) 2022 Novemus Band. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 */

#include <future>
#include <iostream>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/system/system_error.hpp>
#include <boost/test/unit_test.hpp>
#include "../network.h"
#include "../utils.h"

class tcp_echo_session : public std::enable_shared_from_this<tcp_echo_session>
{
    enum { max_length = 1024 };

    char m_data[max_length];
    boost::asio::ip::tcp::socket m_socket;

public:

    tcp_echo_session(boost::asio::io_service &io)
        : m_socket(io)
    {
    }

    boost::asio::ip::tcp::socket& socket()
    {
        return m_socket;
    }

    void start()
    {
        m_socket.async_read_some(
            boost::asio::buffer(m_data, max_length),
            boost::bind(&tcp_echo_session::handle_read, shared_from_this(), boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred)
            );
    }

protected:

    void handle_read(const boost::system::error_code &error, size_t transferred)
    {
        if (!error)
        {
            m_socket.async_write_some(
                boost::asio::buffer(m_data, transferred),
                boost::bind(&tcp_echo_session::handle_write, shared_from_this(), boost::asio::placeholders::error)
                );
        }
    }

    void handle_write(const boost::system::error_code &error)
    {
        if (!error)
        {
            m_socket.async_read_some(
                boost::asio::buffer(m_data, max_length),
                boost::bind(&tcp_echo_session::handle_read, shared_from_this(), boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred)
                );
        }
    }
};

namespace {

class tcp_echo_server
{
    std::future<void> m_work;
    boost::asio::io_service m_io;
    boost::asio::ip::tcp::acceptor m_acceptor;

public:

    tcp_echo_server(unsigned short port)
        : m_acceptor(m_io, boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string("127.0.0.1"), port))
    {
        m_acceptor.non_blocking(true);
        m_acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
    }

    ~tcp_echo_server()
    {
        stop();
    }

    void start()
    {
        start_accept();

        m_work = std::async(std::launch::async, [this]()
        {
            m_io.run();
        });
    }

    void stop()
    {
        if (!m_io.stopped())
            m_io.stop();

        if (m_work.valid())
            m_work.wait();

        m_acceptor.close();
    }

protected:

    void start_accept()
    {
        auto session = std::make_shared<tcp_echo_session>(m_io);
        m_acceptor.async_accept(
            session->socket(),
            boost::bind(&tcp_echo_server::handle_accept, this, session, boost::asio::placeholders::error)
            );
    }

    void handle_accept(std::shared_ptr<tcp_echo_session> session, const boost::system::error_code &error)
    {
        if (!error)
            session->start();

        start_accept();
    }
};

std::shared_ptr<tcp_echo_server> create_tcp_server(unsigned short port)
{
    return std::make_shared<tcp_echo_server>(port);
}


const char HELLO[] = "Hello, Plexus!";

const uint16_t TCP_SERVER_PORT = 8765;
const uint16_t TCP_CLIENT_PORT = 5678;

const boost::asio::ip::tcp::endpoint TCP_SERVER(boost::asio::ip::address::from_string("127.0.0.1"), TCP_SERVER_PORT);
const boost::asio::ip::tcp::endpoint TCP_CLIENT(boost::asio::ip::address::from_string("127.0.0.1"), TCP_CLIENT_PORT);
const boost::asio::ip::tcp::endpoint TCP_REMOTE_SERVER(boost::asio::ip::address::from_string("8.8.8.8"), 80);

}

BOOST_AUTO_TEST_CASE(tcp_echo_exchange)
{
    char buffer[1024];

    auto shorty = plexus::network::create_tcp_client(TCP_REMOTE_SERVER, TCP_CLIENT, 2000, 3);
    BOOST_REQUIRE_THROW(shorty->connect(), boost::system::system_error);
    BOOST_REQUIRE_NO_THROW(shorty->shutdown());

    auto server = create_tcp_server(TCP_SERVER_PORT);
    auto client = plexus::network::create_tcp_client(TCP_SERVER, TCP_CLIENT);

    BOOST_REQUIRE_NO_THROW(server->start());
    BOOST_REQUIRE_NO_THROW(client->connect());

    BOOST_REQUIRE_NO_THROW(BOOST_REQUIRE_EQUAL(client->write((const uint8_t*)HELLO, sizeof(HELLO)), sizeof(HELLO)));
    BOOST_REQUIRE_NO_THROW(BOOST_REQUIRE_EQUAL(client->read((uint8_t*)buffer, sizeof(buffer)), sizeof(HELLO)));
    BOOST_REQUIRE_EQUAL(std::memcmp(buffer, HELLO, sizeof(HELLO)), 0);

    BOOST_REQUIRE_NO_THROW(BOOST_REQUIRE_EQUAL(client->write((const uint8_t*)HELLO, sizeof(HELLO)), sizeof(HELLO)));
    BOOST_REQUIRE_NO_THROW(BOOST_REQUIRE_EQUAL(client->read((uint8_t*)buffer, sizeof(buffer)), sizeof(HELLO)));
    BOOST_REQUIRE_EQUAL(std::memcmp(buffer, HELLO, sizeof(HELLO)), 0);

    BOOST_REQUIRE_NO_THROW(client->shutdown());
    BOOST_REQUIRE_NO_THROW(server->stop());
}
