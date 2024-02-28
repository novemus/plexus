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

#include <logger.h>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/socket_base.hpp>
#include <boost/asio/deadline_timer.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>

namespace plexus { namespace network {

typedef std::function<void(const boost::system::error_code&, size_t)> async_asio_callback;
typedef std::function<void(const async_asio_callback&)> async_asio_call;

template<typename socket_impl> class asio_socket : public socket_impl
{
    size_t execute(const async_asio_call& invoke, const boost::posix_time::time_duration& timeout) noexcept(false)
    {
        boost::asio::deadline_timer timer(m_io);
        if (timeout.ticks() > 0)
        {
            timer.expires_from_now(timeout);
            timer.async_wait([&](const boost::system::error_code& error)
            {
                if(error)
                {
                    if (error == boost::asio::error::operation_aborted)
                        return;

                    _err_ << error.message();
                }

                try
                {
                    socket_impl::lowest_layer().cancel();
                }
                catch (const std::exception &ex)
                {
                    _err_ << ex.what();
                }
            });
        }

        boost::system::error_code code = boost::asio::error::would_block;
        size_t length = 0;

        invoke([&code, &length](const boost::system::error_code& c, size_t l) {
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

public:

    asio_socket(boost::asio::io_service& io) : socket_impl(io), m_io(io)
    {
    }

    template <typename socket_arg>
    asio_socket(boost::asio::io_service& io, socket_arg& option) : socket_impl(io, option), m_io(io)
    {
    }

    template <typename duration_type>
    void wait(boost::asio::socket_base::wait_type type, duration_type timeout) noexcept(false)
    {
        execute([&](const async_asio_callback& callback) {
            socket_impl::lowest_layer().async_wait(type, boost::bind(callback, boost::asio::placeholders::error, 0));
        }, timeout);
    }

    template <typename endpoint_type, typename duration_type>
    void connect(const endpoint_type& endpoint, duration_type timeout) noexcept(false)
    {
        execute([&](const async_asio_callback& callback) {
            socket_impl::lowest_layer().async_connect(endpoint, boost::bind(callback, boost::asio::placeholders::error, 0));
        }, timeout);
    }

    template <typename handshake_type, typename duration_type>
    void handshake(handshake_type type, duration_type timeout) noexcept(false)
    {
        execute([&](const async_asio_callback& callback) {
            socket_impl::async_handshake(type, boost::bind(callback, boost::asio::placeholders::error, 0));
        }, timeout);
    }

    template <typename const_buffer_type, typename duration_type>
    size_t write_some(const const_buffer_type& buffer, duration_type timeout) noexcept(false)
    {
        return execute([&](const async_asio_callback& callback) {
            socket_impl::async_write_some(buffer, callback);
        }, timeout);
    }

    template <typename mutable_buffer_type, typename duration_type>
    size_t read_some(const mutable_buffer_type& buffer, duration_type timeout) noexcept(false)
    {
        return execute([&](const async_asio_callback& callback) {
            socket_impl::async_read_some(buffer, callback);
        }, timeout);
    }

    template <typename const_buffer_type, typename endpoint_type, typename duration_type>
    size_t send_to(const const_buffer_type& buffer, const endpoint_type& endpoint, duration_type timeout) noexcept(false)
    {
        return execute([&](const async_asio_callback& callback) {
            socket_impl::async_send_to(buffer, endpoint, callback);
        }, timeout);
    }

    template <typename mutable_buffer_type, typename endpoint_type, typename duration_type>
    size_t receive_from(const mutable_buffer_type& buffer, endpoint_type& endpoint, duration_type timeout) noexcept(false)
    {
        return execute([&](const async_asio_callback& callback) {
            socket_impl::async_receive_from(buffer, endpoint, callback);
        }, timeout);
    }

private:

    boost::asio::io_service& m_io;
};

}}
