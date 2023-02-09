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
#include <iostream>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/deadline_timer.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <boost/lexical_cast.hpp>
#include "network.h"
#include "log.h"
#include "utils.h"

namespace plexus { namespace network {

class asio_ssl_client : public plexus::network::ssl
{
    typedef std::function<void(const boost::system::error_code&, size_t)> async_callback_t;
    typedef std::function<void(const async_callback_t&)> async_call_t;
    typedef std::shared_ptr<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>> ssl_stream_socket_ptr;

    boost::asio::io_service         m_io;
    boost::asio::ssl::context       m_ssl;
    ssl_stream_socket_ptr           m_socket;
    boost::asio::deadline_timer     m_timer;
    boost::asio::ip::tcp::endpoint  m_endpoint;
    boost::posix_time::milliseconds m_timeout;

    size_t exec(const async_call_t& async_call)
    {
        m_timer.expires_from_now(m_timeout);
        m_timer.async_wait([&](const boost::system::error_code& error) {
            if(error)
            {
                if (error == boost::asio::error::operation_aborted)
                    return;

                _err_ << error.message();
            }

            try
            {
                m_socket->lowest_layer().cancel();
            }
            catch (const std::exception &ex)
            {
                _err_ << ex.what();
            }
        });

        boost::system::error_code code = boost::asio::error::would_block;
        size_t length = 0;

        async_call([&code, &length](const boost::system::error_code& c, size_t l) {
            code = c;
            length = l;
        });

        do {
            m_io.run_one();
        } while (code == boost::asio::error::would_block);

        m_io.reset();

        if (code)
            throw boost::system::system_error(code);

        return length;
    }

    boost::asio::ip::tcp::endpoint resolve_endpoint(const endpoint& address)
    {
        boost::asio::ip::tcp::resolver resolver(m_io);
        boost::asio::ip::tcp::resolver::query query(address.first, std::to_string(address.second));
        return *resolver.resolve(query);
    }

public:

    asio_ssl_client(const endpoint& remote, const std::string& cert, const std::string& key, const std::string& ca)
        : m_ssl(boost::asio::ssl::context::sslv23)
        , m_timer(m_io)
        , m_endpoint(resolve_endpoint(remote))
        , m_timeout(plexus::utils::getenv<int64_t>("PLEXUS_SSL_TIMEOUT", 5000))
    {
        m_ssl.set_options(boost::asio::ssl::context::default_workarounds | boost::asio::ssl::context::sslv23_client);
        if (!cert.empty() && !key.empty())
        {
            m_ssl.use_certificate_file(cert, boost::asio::ssl::context::pem);
            m_ssl.use_private_key_file(key, boost::asio::ssl::context::pem);
        }

        if (!ca.empty())
        {
            m_ssl.set_verify_mode(boost::asio::ssl::verify_peer | boost::asio::ssl::verify_fail_if_no_peer_cert | boost::asio::ssl::verify_client_once );
            m_ssl.load_verify_file(ca);
        }

        m_socket = std::make_shared<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>(m_io, m_ssl);
    }

    void connect() noexcept(false) override
    {
        exec([&](const async_callback_t& callback)
        {
            m_socket->lowest_layer().async_connect(m_endpoint, boost::bind(callback, boost::asio::placeholders::error, 0));
        });

        exec([&](const async_callback_t& callback)
        {
            m_socket->async_handshake(boost::asio::ssl::stream_base::client, boost::bind(callback, boost::asio::placeholders::error, 0));
        });
    }

    void shutdown() noexcept(true) override
    {
        if (m_socket->lowest_layer().is_open())
        {
            boost::system::error_code ec;
            m_socket->lowest_layer().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
            m_socket->lowest_layer().close(ec);
        }
    }

    size_t read(uint8_t* buffer, size_t len) noexcept(false) override
    {
        m_socket->lowest_layer().wait(boost::asio::ip::tcp::socket::wait_read);

        size_t size = exec([&](const async_callback_t& callback)
        {
            m_socket->async_read_some(boost::asio::buffer(buffer, len), callback);
        });

        _trc_ << m_endpoint.address() << ":" << m_endpoint.port() << " >>>>> " << utils::to_hexadecimal(buffer, size);

        if (size == 0)
            throw std::runtime_error("can't read data");

        return size;
    }

    size_t write(const uint8_t* buffer, size_t len) noexcept(false) override
    {
        m_socket->lowest_layer().wait(boost::asio::ip::tcp::socket::wait_write);

        size_t size = exec([&](const async_callback_t& callback)
        {
            m_socket->async_write_some(boost::asio::buffer(buffer, len), callback);
        });

        _trc_ << m_endpoint.address() << ":" << m_endpoint.port() << " <<<<< " << utils::to_hexadecimal(buffer, size);

        if (size < len)
            throw std::runtime_error("can't write data");

        return size;
    }
};

std::shared_ptr<ssl> create_ssl_client(const endpoint& remote, const std::string& cert, const std::string& key, const std::string& ca)
{
    return std::make_shared<asio_ssl_client>(remote, cert, key, ca);
}

}}
