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
#include "network.h"
#include "utils.h"
#include <logger.h>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/date_time/posix_time/posix_time_config.hpp>
#include <boost/date_time/posix_time/posix_time_duration.hpp>

namespace plexus { namespace network {

template<class socket>
struct asio_tcp_client_base : public tcp
{
    template <typename ...socket_args>
    asio_tcp_client_base(const boost::asio::ip::tcp::endpoint& remote, socket_args& ...options)
        : m_socket(m_io, options...)
        , m_remote(remote)
    {
        static const size_t SOCKET_BUFFER_SIZE = 1048576;

        m_socket.lowest_layer().open(m_remote.protocol());

        m_socket.lowest_layer().non_blocking(true);
        m_socket.lowest_layer().set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
        m_socket.lowest_layer().set_option(boost::asio::socket_base::keep_alive(true));
        m_socket.lowest_layer().set_option(boost::asio::socket_base::send_buffer_size(SOCKET_BUFFER_SIZE));
        m_socket.lowest_layer().set_option(boost::asio::socket_base::receive_buffer_size(SOCKET_BUFFER_SIZE));
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

    void connect(int64_t timeout) noexcept(false) override
    {
        m_socket.connect(m_remote, boost::posix_time::milliseconds(timeout));
    }

    void wait(boost::asio::socket_base::wait_type what, int64_t timeout = 10000) noexcept(false) override
    {
        m_socket.wait(what, boost::posix_time::milliseconds(timeout));
    }

    size_t read(uint8_t* buffer, size_t len, int64_t timeout) noexcept(false) override
    {
        size_t size = m_socket.read_some(boost::asio::buffer(buffer, len), boost::posix_time::milliseconds(timeout));

        _trc_ << m_remote << " >>>>> " << std::make_pair(buffer, size);

        if (size == 0)
            throw std::runtime_error("can't read data");

        return size;
    }

    size_t write(const uint8_t* buffer, size_t len, int64_t timeout) noexcept(false) override
    {
        size_t size = m_socket.write_some(boost::asio::buffer(buffer, len), boost::posix_time::milliseconds(timeout));

        _trc_ << m_remote << " <<<<< " << std::make_pair(buffer, size);

        if (size < len)
            throw std::runtime_error("can't write data");

        return size;
    }

protected:

    boost::asio::io_service         m_io;
    asio_socket<socket>             m_socket;
    boost::asio::ip::tcp::endpoint  m_remote;
};

class asio_tcp_client : public asio_tcp_client_base<asio_socket<boost::asio::ip::tcp::socket>>
{
    typedef asio_tcp_client_base<boost::asio::ip::tcp::socket> base;

public:

    asio_tcp_client(const boost::asio::ip::tcp::endpoint& remote, const boost::asio::ip::tcp::endpoint& local, uint8_t hops)
        : asio_tcp_client_base(remote)
    {
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
        : asio_tcp_client_base(remote, ssl)
        , m_ssl(std::move(ssl))
    {
    }

    void connect(int64_t timeout) noexcept(false) override
    {
        base::connect(timeout);
        m_socket.handshake(boost::asio::ssl::stream_base::client, boost::posix_time::milliseconds(timeout));
    }

private:

    boost::asio::ssl::context m_ssl;
};

std::shared_ptr<tcp> create_tcp_client(const boost::asio::ip::tcp::endpoint& remote, const boost::asio::ip::tcp::endpoint& local, uint8_t hops)
{
    return std::make_shared<asio_tcp_client>(remote, local, hops);
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
