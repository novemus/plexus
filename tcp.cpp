/*
 * Copyright (c) 2022 Novemus Band. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 */

#include <map>
#include <iostream>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/deadline_timer.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include "network.h"
#include "utils.h"
#include "log.h"


namespace plexus { namespace network {

class asio_tcp_channel : public tcp, public std::enable_shared_from_this<asio_tcp_channel>
{
    typedef std::function<void(const boost::system::error_code&, size_t)> async_callback_t;
    typedef std::function<void(const async_callback_t&)> async_call_t;

    boost::asio::ip::tcp::endpoint m_local;
    boost::asio::io_service        m_io;
    boost::asio::ip::tcp::socket   m_socket;
    boost::asio::deadline_timer    m_timer;
    int64_t                        m_timeout = 0;

    size_t exec(const async_call_t& async_call)
    {
        m_timer.expires_from_now(boost::posix_time::milliseconds(m_timeout));
        m_timer.async_wait([&](const boost::system::error_code& error) {
            if(error)
            {
                if (error == boost::asio::error::operation_aborted)
                    return;

                _err_ << error.message();
            }

            try
            {
                m_socket.cancel();
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
        boost::asio::ip::tcp::resolver::query query(boost::asio::ip::tcp::v4(), address.first, std::to_string(address.second));
        boost::asio::ip::tcp::endpoint endpoint = *resolver.resolve(query);

        return endpoint;
    }

    static const size_t SOCKET_BUFFER_SIZE = 1048576;

public:

    asio_tcp_channel(const endpoint& local)
        : m_local(resolve_endpoint(local))
        , m_socket(m_io)
        , m_timer(m_io)
    {
    }

    ~asio_tcp_channel()
    {
        shutdown();
    }

    void shutdown() noexcept(true) override
    {
        if (m_socket.is_open())
        {
            boost::system::error_code ec;
            m_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
            m_socket.close(ec);
        }
    }

    void accept(const endpoint& remote, int64_t timeout) noexcept(false) override
    {
        m_timeout = timeout;

        auto timer = [start = boost::posix_time::microsec_clock::universal_time()]()
        {
            return boost::posix_time::microsec_clock::universal_time() - start;
        };

        auto peer = resolve_endpoint(remote);

        boost::asio::ip::tcp::acceptor acceptor(m_io, m_local);
        acceptor.non_blocking(true);
        acceptor.set_option(boost::asio::socket_base::send_buffer_size(SOCKET_BUFFER_SIZE));
        acceptor.set_option(boost::asio::socket_base::receive_buffer_size(SOCKET_BUFFER_SIZE));

        do
        {
            exec([&](const async_callback_t& callback)
            {
                acceptor.async_accept(m_socket, boost::bind(callback, boost::asio::placeholders::error, 0));
            });

            if (m_socket.lowest_layer().remote_endpoint() == peer)
            {
                m_socket.non_blocking(true);
                m_socket.set_option(boost::asio::socket_base::send_buffer_size(SOCKET_BUFFER_SIZE));
                m_socket.set_option(boost::asio::socket_base::receive_buffer_size(SOCKET_BUFFER_SIZE));

                boost::system::error_code ec;
                acceptor.close(ec);

                return;
            }

            shutdown();
        } 
        while (timer().total_milliseconds() < timeout);

        throw boost::system::error_code(boost::asio::error::operation_aborted);
    }

    void connect(const endpoint& remote, int64_t timeout, uint8_t hops) noexcept(false) override
    {
        m_timeout = timeout;

        m_socket.open(m_local.protocol());

        m_socket.non_blocking(true);
        m_socket.set_option(boost::asio::socket_base::send_buffer_size(SOCKET_BUFFER_SIZE));
        m_socket.set_option(boost::asio::socket_base::receive_buffer_size(SOCKET_BUFFER_SIZE));
        m_socket.set_option(boost::asio::ip::unicast::hops(hops));

        m_socket.bind(m_local);

        auto peer = resolve_endpoint(remote);

        exec([&](const async_callback_t& callback)
        {
            m_socket.async_connect(peer, boost::bind(callback, boost::asio::placeholders::error, 0));
        });
    }

    size_t read(std::shared_ptr<transfer> tran) noexcept(false) override
    {
        size_t size = exec([&](const async_callback_t& callback)
        {
            m_socket.async_read_some(boost::asio::buffer(tran->buffer), callback);
        });

        _trc_ << m_socket.remote_endpoint().address() << ":" << m_socket.remote_endpoint().port() << " >>>>> " << utils::to_hexadecimal(tran->buffer.data(), size);

        if (size == 0)
            throw std::runtime_error("can't read data");

        return size;
    }

    size_t write(std::shared_ptr<transfer> tran) noexcept(false) override
    {
        size_t size = exec([&](const async_callback_t& callback)
        {
            m_socket.async_write_some(boost::asio::buffer(tran->buffer), callback);
        });

        _trc_ << m_socket.remote_endpoint().address() << ":" << m_socket.remote_endpoint().port() << " <<<<< " << utils::to_hexadecimal(tran->buffer.data(), size);

        if (size < tran->buffer.size())
            throw std::runtime_error("can't write data");

        return size;
    }
};

std::shared_ptr<tcp> create_tcp_channel(const endpoint& local)
{
    return std::make_shared<asio_tcp_channel>(local);
}

}}
