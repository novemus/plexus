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

// raw tcp transport tests

namespace {

const plexus::network::endpoint lep = std::make_pair("127.0.0.1", 1234);
const plexus::network::endpoint rep = std::make_pair("127.0.0.1", 4321);

boost::test_tools::assertion_result is_enabled(boost::unit_test::test_unit_id)
{
#ifdef _WIN32
    boost::test_tools::assertion_result res(false);
    res.message() << "disabled for windows";
    return res;
#else
    if (getuid() != 0)
    {
        boost::test_tools::assertion_result res(false);
        res.message() << "root privileges are required";
        return res;
    }
    return boost::test_tools::assertion_result(true);
#endif
}

void check_raw_tcp(const plexus::network::endpoint& from, const plexus::network::endpoint& to, std::shared_ptr<plexus::network::buffer> send, std::shared_ptr<plexus::network::buffer> recv)
{
    std::shared_ptr<plexus::network::raw::ip_packet> in = std::static_pointer_cast<plexus::network::raw::ip_packet>(recv);
    std::shared_ptr<plexus::network::raw::tcp_packet> out = std::dynamic_pointer_cast<plexus::network::raw::tcp_packet>(send);

    BOOST_REQUIRE_EQUAL(in->protocol(), IPPROTO_TCP);
    BOOST_REQUIRE_EQUAL(out->size(), in->total_length() - in->header_length());

    auto tcp = in->payload<plexus::network::raw::tcp_packet>();

    if (from == to)
    {
        BOOST_REQUIRE_EQUAL(from.first, in->source_address().to_string());
        BOOST_REQUIRE_EQUAL(to.first, in->destination_address().to_string());
        BOOST_REQUIRE_EQUAL(out->source_port(), tcp->dest_port());
        BOOST_REQUIRE_EQUAL(out->dest_port(), tcp->source_port());
    }
    else
    {
        BOOST_REQUIRE_EQUAL(from.first, in->destination_address().to_string());
        BOOST_REQUIRE_EQUAL(to.first, in->source_address().to_string());
        BOOST_REQUIRE_EQUAL(out->dest_port(), tcp->dest_port());
        BOOST_REQUIRE_EQUAL(out->source_port(), tcp->source_port());
    }

    auto in_data = tcp->push_head(4);
    auto out_data = out->push_head(4);

    BOOST_REQUIRE_EQUAL(std::memcmp(in_data.data(), out_data.data(), out_data.size()), 0);
}

}

BOOST_AUTO_TEST_CASE(sync_raw_tcp_exchange, * boost::unit_test::precondition(is_enabled))
{
    const std::initializer_list<uint8_t> payload = { 
        plexus::utils::random<uint8_t>(),
        plexus::utils::random<uint8_t>(),
        plexus::utils::random<uint8_t>(),
        plexus::utils::random<uint8_t>()
    };

    auto lend = plexus::network::raw::create_tcp_transport(lep);
    auto rend = plexus::network::raw::create_tcp_transport(rep);

    auto send = plexus::network::raw::tcp_packet::make_syn_packet(lep, rep);
    auto recv = std::make_shared<plexus::network::buffer>(1500);

    BOOST_REQUIRE_NO_THROW(lend->send(rep, send));
    BOOST_REQUIRE_NO_THROW(rend->receive(lep, recv));
    
    check_raw_tcp(lep, rep, send, recv);

    BOOST_REQUIRE_NO_THROW(lend->send(rep, send));
    BOOST_REQUIRE_NO_THROW(rend->receive(lep, recv));

    check_raw_tcp(lep, rep, send, recv);

    BOOST_REQUIRE_THROW(rend->receive(lep, recv), boost::system::system_error);
}

BOOST_AUTO_TEST_CASE(async_raw_tcp_exchange, * boost::unit_test::precondition(is_enabled))
{
    auto lend = plexus::network::raw::create_tcp_transport(lep);
    auto rend = plexus::network::raw::create_tcp_transport(rep);

    auto out = plexus::network::raw::tcp_packet::make_syn_packet(lep, rep);
    auto in = std::make_shared<plexus::network::raw::ip_packet>(1500);

    auto send = [&]()
    {
        BOOST_REQUIRE_NO_THROW(lend->send(rep, out));
        BOOST_REQUIRE_NO_THROW(lend->send(rep, out));
        BOOST_REQUIRE_NO_THROW(lend->send(rep, out));
    };

    auto recv = [&]()
    {
        BOOST_REQUIRE_NO_THROW(rend->receive(lep, in));
        check_raw_tcp(lep, rep, out, in);

        BOOST_REQUIRE_NO_THROW(rend->receive(lep, in));
        check_raw_tcp(lep, rep, out, in);

        BOOST_REQUIRE_NO_THROW(rend->receive(lep, in));
        check_raw_tcp(lep, rep, out, in);
    };

    auto l = std::async(std::launch::async, send);
    auto r = std::async(std::launch::async, recv);

    BOOST_REQUIRE_NO_THROW(l.wait());
    BOOST_REQUIRE_NO_THROW(r.wait());
}

// tcp client tests

class tcp_echo_session
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
            boost::bind(&tcp_echo_session::handle_read, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred)
            );
    }

protected:

    void handle_read(const boost::system::error_code &error, size_t transferred)
    {
        if (!error)
        {
            m_socket.async_write_some(
                boost::asio::buffer(m_data, transferred),
                boost::bind(&tcp_echo_session::handle_write, this, boost::asio::placeholders::error)
                );
        }
        else
            delete this;
    }

    void handle_write(const boost::system::error_code &error)
    {
        if (!error)
        {
            m_socket.async_read_some(
                boost::asio::buffer(m_data, max_length),
                boost::bind(&tcp_echo_session::handle_read, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred)
                );
        }
        else
            delete this;
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
        : m_acceptor(m_io, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port))
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
        tcp_echo_session* session = new tcp_echo_session(m_io);
        m_acceptor.async_accept(
            session->socket(),
            boost::bind(&tcp_echo_server::handle_accept, this, session, boost::asio::placeholders::error)
            );
    }

    void handle_accept(tcp_echo_session *session, const boost::system::error_code &error)
    {
        if (!error)
            session->start();
        else
            delete session;

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

const plexus::network::endpoint TCP_SERVER("127.0.0.1", TCP_SERVER_PORT);
const plexus::network::endpoint TCP_CLIENT("127.0.0.1", TCP_CLIENT_PORT);
const plexus::network::endpoint TCP_REMOTE_SERVER("8.8.8.8", 80);

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
