/*
 * Copyright (c) 2022 Novemus Band. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 */

#include "socket.h"
#include "utils.h"
#include <logger.h>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>

namespace plexus { namespace network {

template<class socket>
struct asio_tcp_client_base : public tcp
{
    asio_tcp_client_base(const boost::asio::ip::tcp::endpoint& remote, int64_t timeout)
        : m_socket(m_io)
        , m_remote(remote)
        , m_timeout(timeout)
    {
    }

    template <typename socket_arg>
    asio_tcp_client_base(socket_arg& option, const boost::asio::ip::tcp::endpoint& remote, int64_t timeout)
        : m_socket(m_io, option)
        , m_remote(remote)
        , m_timeout(timeout)
    {
    }

    ~asio_tcp_client_base()
    {
        shutdown();
    }

    void shutdown() noexcept(true) override
    {
        if (m_socket.lowest_layer().is_open())
        {
            boost::system::error_code ec;
            m_socket.lowest_layer().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
            m_socket.lowest_layer().close(ec);
        }
    }

    void connect() noexcept(false) override
    {
        m_socket.connect(m_remote, m_timeout);
    }

    size_t read(uint8_t* buffer, size_t len, bool deferred) noexcept(false) override
    {
        if (deferred)
            m_socket.lowest_layer().wait(boost::asio::ip::tcp::socket::wait_read);

        size_t size = m_socket.read_some(boost::asio::buffer(buffer, len), m_timeout);

        _trc_ << m_remote << " >>>>> " << std::make_pair(buffer, size);

        if (size == 0)
            throw std::runtime_error("can't read data");

        return size;
    }

    size_t write(const uint8_t* buffer, size_t len, bool deferred) noexcept(false) override
    {
        if (deferred)
            m_socket.lowest_layer().wait(boost::asio::ip::tcp::socket::wait_write);

        size_t size = m_socket.write_some(boost::asio::buffer(buffer, len), m_timeout);

        _trc_ << m_remote << " <<<<< " << std::make_pair(buffer, size);

        if (size < len)
            throw std::runtime_error("can't write data");

        return size;
    }

protected:

    boost::asio::io_service         m_io;
    asio_socket<socket>             m_socket;
    boost::asio::ip::tcp::endpoint  m_remote;
    boost::posix_time::milliseconds m_timeout;
};

class asio_tcp_client : public asio_tcp_client_base<asio_socket<boost::asio::ip::tcp::socket>>
{
    typedef asio_tcp_client_base<boost::asio::ip::tcp::socket> base;

public:

    asio_tcp_client(const boost::asio::ip::tcp::endpoint& remote, const boost::asio::ip::tcp::endpoint& local, int64_t timeout, uint8_t hops)
        : asio_tcp_client_base(remote, timeout)
    {
        static const size_t SOCKET_BUFFER_SIZE = 1048576;

        m_socket.open(m_remote.protocol());

        m_socket.non_blocking(true);
        m_socket.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
        m_socket.set_option(boost::asio::socket_base::send_buffer_size(SOCKET_BUFFER_SIZE));
        m_socket.set_option(boost::asio::socket_base::receive_buffer_size(SOCKET_BUFFER_SIZE));
        m_socket.set_option(boost::asio::ip::unicast::hops(hops));

        if (local.port())
            m_socket.bind(local);
    }
};

class asio_ssl_client : public asio_tcp_client_base<asio_socket<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>>
{
    typedef asio_tcp_client_base<asio_socket<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>> base;

public:

    asio_ssl_client(const boost::asio::ip::tcp::endpoint& remote, boost::asio::ssl::context&& ssl)
        : asio_tcp_client_base(ssl, remote, plexus::utils::getenv<int64_t>("PLEXUS_SSL_TIMEOUT", 5000))
        , m_ssl(std::move(ssl))
    {
    }

    void connect() noexcept(false) override
    {
        base::connect();
        m_socket.handshake(boost::asio::ssl::stream_base::client, m_timeout);
    }

private:

    boost::asio::ssl::context m_ssl;
};

std::shared_ptr<tcp> create_tcp_client(const boost::asio::ip::tcp::endpoint& remote, const boost::asio::ip::tcp::endpoint& local, int64_t timeout, uint8_t hops)
{
    return std::make_shared<asio_tcp_client>(remote, local, timeout, hops);
}

std::shared_ptr<tcp> create_ssl_client(const boost::asio::ip::tcp::endpoint& remote, const std::string& cert, const std::string& key, const std::string& ca)
{
    boost::asio::ssl::context ssl = boost::asio::ssl::context(boost::asio::ssl::context::sslv23);
    
    ssl.set_options(boost::asio::ssl::context::default_workarounds | boost::asio::ssl::context::sslv23_client);
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

    return std::make_shared<asio_ssl_client>(remote, std::move(ssl));
}

}}
