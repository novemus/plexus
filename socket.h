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
#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/socket_base.hpp>
#include <boost/asio/deadline_timer.hpp>
#include <boost/date_time/posix_time/posix_time_duration.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>

namespace plexus { namespace network {

template<typename socket_impl, typename endpoint_type, int64_t timeout_ms> class asio_socket : public socket_impl
{
    static bool is_matched(const endpoint_type& source, const endpoint_type& match)
    {
        return (match.address().is_unspecified() || match.address() == source.address()) && (match.port() == 0 || match.port() == source.port());
    }

    size_t execute(const std::function<size_t()>& function, int64_t timeout = timeout_ms) noexcept(false)
    {
        boost::asio::deadline_timer timer(m_io);
        if (timeout > 0)
        {
            timer.expires_from_now(boost::posix_time::milliseconds(timeout));
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

        size_t res = function();

        timer.cancel();

        return res;
    }

public:

    template<typename protocol_type>
    asio_socket(boost::asio::io_service& io, const protocol_type& protocol)
        : asio_socket(socket_impl(io), io, protocol)
    {
    }

    asio_socket(boost::asio::io_service& io, const endpoint_type& remote)
        : asio_socket(socket_impl(io), io, remote.protocol(), remote)
    {
    }

    asio_socket(socket_impl&& impl, boost::asio::io_service& io, const endpoint_type& remote) 
        : asio_socket(std::move(impl), io, remote.protocol(), remote)
    {
    }

    template<typename protocol_type>
    asio_socket(socket_impl&& impl, boost::asio::io_service& io, const protocol_type& protocol, const endpoint_type& remote = endpoint_type()) 
        : socket_impl(std::move(impl)), m_io(io), m_remote(remote)
    {
        socket_impl::lowest_layer().open(protocol);

        static const size_t SOCKET_BUFFER_SIZE = 1048576;

        socket_impl::lowest_layer().non_blocking(true);
        socket_impl::lowest_layer().set_option(boost::asio::socket_base::reuse_address(true));
        socket_impl::lowest_layer().set_option(boost::asio::socket_base::send_buffer_size(SOCKET_BUFFER_SIZE));
        socket_impl::lowest_layer().set_option(boost::asio::socket_base::receive_buffer_size(SOCKET_BUFFER_SIZE));
    }

    void wait(boost::asio::socket_base::wait_type type, boost::asio::yield_context yield, int64_t timeout = timeout_ms) noexcept(false)
    {
        execute([&]() {
            socket_impl::lowest_layer().async_wait(type, yield);
            return 0;
        }, timeout);
    }

    void connect(boost::asio::yield_context yield, int64_t timeout = timeout_ms) noexcept(false)
    {
        execute([&]() {
            socket_impl::lowest_layer().async_connect(m_remote, yield);
            return 0;
        }, timeout);
    }

    void shutdown() noexcept(true)
    {
        if (socket_impl::lowest_layer().is_open())
        {
            boost::system::error_code ec;
            socket_impl::lowest_layer().shutdown(boost::asio::socket_base::shutdown_both, ec);
            socket_impl::lowest_layer().close(ec);
        }
    }

    template <typename handshake_type>
    void handshake(handshake_type type, boost::asio::yield_context yield, int64_t timeout = timeout_ms) noexcept(false)
    {
        execute([&]() {
            socket_impl::async_handshake(type, yield);
            return 0;
        }, timeout);
    }

    template <typename const_buffer_type>
    size_t write_some(const const_buffer_type& buffer, boost::asio::yield_context yield, int64_t timeout = timeout_ms) noexcept(false)
    {
        return execute([&]() {
            return socket_impl::async_write_some(buffer, yield);
        }, timeout);
    }

    template <typename mutable_buffer_type>
    size_t read_some(const mutable_buffer_type& buffer, boost::asio::yield_context yield, int64_t timeout = timeout_ms) noexcept(false)
    {
        return execute([&]() {
            return socket_impl::async_read_some(buffer, yield);
        }, timeout);
    }

    template <typename const_buffer_type>
    size_t write(const const_buffer_type& buffer, boost::asio::yield_context yield, int64_t timeout = timeout_ms) noexcept(false)
    {
        return execute([&]() {
            return boost::asio::async_write(static_cast<socket_impl&>(*this), buffer, yield);
        }, timeout);
    }

    template <typename mutable_buffer_type>
    size_t read(const mutable_buffer_type& buffer, boost::asio::yield_context yield, int64_t timeout = timeout_ms) noexcept(false)
    {
        return execute([&]() {
            return boost::asio::async_read(static_cast<socket_impl&>(*this), buffer, yield);
        }, timeout);
    }

    template <typename const_buffer_type>
    size_t send_to(const const_buffer_type& buffer, const endpoint_type& endpoint, boost::asio::yield_context yield, int64_t timeout = timeout_ms) noexcept(false)
    {
        return execute([&]() {
            return socket_impl::async_send_to(buffer, endpoint, yield);
        }, timeout);
    }

    template <typename mutable_buffer_type>
    size_t receive_from(const mutable_buffer_type& buffer, const endpoint_type& endpoint, boost::asio::yield_context yield, int64_t timeout = timeout_ms) noexcept(false)
    {
        auto timer = [start = boost::posix_time::microsec_clock::universal_time()]()
        {
            return boost::posix_time::microsec_clock::universal_time() - start;
        };

        while (timer().total_milliseconds() < timeout)
        {
            endpoint_type source;

            size_t size = execute([&]() {
                return socket_impl::async_receive_from(buffer, source, yield);
            }, timeout - timer().total_milliseconds());

            if (is_matched(source, endpoint))
                return size;
        }

        throw boost::system::error_code(boost::asio::error::operation_aborted);
    }

private:

    boost::asio::io_service& m_io;
    endpoint_type m_remote;
};

}}
