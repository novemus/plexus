#include <future>
#include <cstdlib>
#include <iostream>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/test/unit_test.hpp>
#include "../network.h"


class ssl_echo_session
{
    enum
    {
        max_length = 1024
    };

    char m_data[max_length];
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> m_socket;

public:

    ssl_echo_session(boost::asio::io_service &io, boost::asio::ssl::context &ssl)
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
            boost::bind(&ssl_echo_session::handle_handshake, this, boost::asio::placeholders::error)
            );
    }

protected:

    void handle_handshake(const boost::system::error_code &error)
    {
        if (!error)
        {
            m_socket.async_read_some(
                boost::asio::buffer(m_data, max_length),
                boost::bind(&ssl_echo_session::handle_read, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred)
                );
        }
        else
        {
            delete this;
        }
    }

    void handle_read(const boost::system::error_code &error,
                     size_t bytes_transferred)
    {
        if (!error)
        {
            boost::asio::async_write(
                m_socket,
                boost::asio::buffer(m_data, bytes_transferred),
                boost::bind(&ssl_echo_session::handle_write, this, boost::asio::placeholders::error)
                );
        }
        else
        {
            delete this;
        }
    }

    void handle_write(const boost::system::error_code &error)
    {
        if (!error)
        {
            m_socket.async_read_some(
                boost::asio::buffer(m_data, max_length),
                boost::bind(&ssl_echo_session::handle_read, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred)
                );
        }
        else
        {
            delete this;
        }
    }
};

class ssl_echo_server
{
    std::future<void> m_work;
    boost::asio::io_service m_io;
    boost::asio::ip::tcp::acceptor m_acceptor;
    boost::asio::ssl::context m_ssl;

public:

    ssl_echo_server(unsigned short port, const std::string& crt, const std::string& key, const std::string& ca = "")
        : m_acceptor(m_io, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)),
          m_ssl(boost::asio::ssl::context::sslv23)
    {
        m_ssl.set_options(boost::asio::ssl::context::default_workarounds | boost::asio::ssl::context::no_sslv2);
        m_ssl.use_certificate_file(crt, boost::asio::ssl::context::pem);
        m_ssl.use_private_key_file(key, boost::asio::ssl::context::pem);
        if (!ca.empty())
        {
            m_ssl.set_verify_mode(SSL_VERIFY_PEER);
            m_ssl.load_verify_file(ca);
        }
    }

    ~ssl_echo_server()
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
    }

protected:

    void start_accept()
    {
        ssl_echo_session* session = new ssl_echo_session(m_io, m_ssl);
        m_acceptor.async_accept(
            session->socket(),
            boost::bind(&ssl_echo_server::handle_accept, this, session, boost::asio::placeholders::error)
            );
    }

    void handle_accept(ssl_echo_session *session, const boost::system::error_code &error)
    {
        if (!error)
        {
            session->start();
        }
        else
        {
            delete session;
        }

        start_accept();
    }
};

BOOST_AUTO_TEST_CASE(no_check_certs)
{
    ssl_echo_server server(4433, "./certs/server.crt", "./certs/server.key");
    BOOST_REQUIRE_NO_THROW(server.start());

    std::shared_ptr<plexus::network::ssl> client(plexus::network::create_ssl_client("127.0.0.1:4433"));
    BOOST_REQUIRE_NO_THROW(client->connect());

    char buffer[1024];

    std::strcpy(buffer, "hello");
    BOOST_REQUIRE_NO_THROW(BOOST_CHECK_EQUAL(client->write((uint8_t *)buffer, strlen(buffer) + 1), strlen(buffer) + 1));
    BOOST_REQUIRE_NO_THROW(BOOST_CHECK_EQUAL(client->read((uint8_t *)buffer, sizeof(buffer)), strlen(buffer) + 1));
    BOOST_CHECK_EQUAL(std::strncmp(buffer, "hello", 1024), 0);

    std::strcpy(buffer, "bye bye");
    BOOST_REQUIRE_NO_THROW(BOOST_CHECK_EQUAL(client->write((uint8_t *)buffer, strlen(buffer) + 1), strlen(buffer) + 1));
    BOOST_REQUIRE_NO_THROW(BOOST_CHECK_EQUAL(client->read((uint8_t *)buffer, sizeof(buffer)), strlen(buffer) + 1));
    BOOST_CHECK_EQUAL(std::strncmp(buffer, "bye bye", 1024), 0);

    BOOST_REQUIRE_NO_THROW(client->shutdown());
    BOOST_REQUIRE_NO_THROW(server.stop());
}

BOOST_AUTO_TEST_CASE(check_certs)
{
    ssl_echo_server server(4433, "./certs/server.crt", "./certs/server.key", "./certs/ca.crt");
    BOOST_REQUIRE_NO_THROW(server.start());

    std::shared_ptr<plexus::network::ssl> client(
        plexus::network::create_ssl_client("127.0.0.1:4433", "./certs/client.crt", "./certs/client.key", "./certs/ca.crt")
        );
    BOOST_REQUIRE_NO_THROW(client->connect());

    char buffer[1024];
    std::strcpy(buffer, "hello");
    BOOST_REQUIRE_NO_THROW(BOOST_CHECK_EQUAL(client->write((uint8_t*)buffer, strlen(buffer) + 1), strlen(buffer) + 1));
    BOOST_REQUIRE_NO_THROW(BOOST_CHECK_EQUAL(client->read((uint8_t*)buffer, sizeof(buffer)), strlen(buffer) + 1));
    BOOST_CHECK_EQUAL(std::strncmp(buffer, "hello", 1024), 0);

    std::strcpy(buffer, "bye bye");
    BOOST_REQUIRE_NO_THROW(BOOST_CHECK_EQUAL(client->write((uint8_t*)buffer, strlen(buffer) + 1), strlen(buffer) + 1));
    BOOST_REQUIRE_NO_THROW(BOOST_CHECK_EQUAL(client->read((uint8_t*)buffer, sizeof(buffer)), strlen(buffer) + 1));
    BOOST_CHECK_EQUAL(std::strncmp(buffer, "bye bye", 1024), 0);

    BOOST_REQUIRE_NO_THROW(client->shutdown());
    BOOST_REQUIRE_NO_THROW(server.stop());
}

BOOST_AUTO_TEST_CASE(mistakes)
{
    std::shared_ptr<plexus::network::ssl> client(
        plexus::network::create_ssl_client("127.0.0.1:4433")
        );
    BOOST_REQUIRE_THROW(client->connect(), std::runtime_error);
    BOOST_REQUIRE_NO_THROW(client->shutdown());

    ssl_echo_server server(4433, "./certs/server.crt", "./certs/server.key");
    BOOST_REQUIRE_NO_THROW(server.start());
    
    client = plexus::network::create_ssl_client("127.0.0.1:4433", "", "", "", 2);
    BOOST_REQUIRE_NO_THROW(client->connect());

    char buffer[1024];
    BOOST_REQUIRE_THROW(client->read((uint8_t*)buffer, sizeof(buffer)), plexus::network::timeout_error);

    BOOST_REQUIRE_NO_THROW(client->shutdown());
    BOOST_REQUIRE_NO_THROW(server.stop());
}
