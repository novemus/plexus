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
#include <mutex>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/deadline_timer.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include "network.h"
#include "utils.h"
#include "log.h"


namespace plexus { namespace network {

class asio_udp_channel : public udp, public std::enable_shared_from_this<asio_udp_channel>
{
    typedef std::map<std::pair<std::string, std::string>, boost::asio::ip::udp::endpoint> endpoint_cache_t;
    typedef std::function<void(const boost::system::error_code&, size_t)> async_io_callback_t;
    typedef std::function<void(const async_io_callback_t&)> async_io_call_t;

    boost::asio::io_service      m_io;
    boost::asio::ip::udp::socket m_socket;
    boost::asio::deadline_timer  m_timer;
    endpoint_cache_t             m_remotes;
    std::mutex                   m_mutex;

    size_t exec(const async_io_call_t& async_io_call, int64_t timeout)
    {
        m_timer.expires_from_now(boost::posix_time::milliseconds(timeout));
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

        async_io_call([&code, &length](const boost::system::error_code& c, size_t l) {
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

    boost::asio::ip::udp::endpoint resolve_endpoint(const std::string& host, const std::string& service)
    {
        auto key = std::make_pair(host, service);
        {
            std::lock_guard<std::mutex> lock(m_mutex);

            auto iter = m_remotes.find(key);
            if (iter != m_remotes.end())
                return iter->second;
        }

        boost::asio::ip::udp::resolver resolver(m_io);
        boost::asio::ip::udp::resolver::query query(boost::asio::ip::udp::v4(), host, service);
        boost::asio::ip::udp::endpoint endpoint = *resolver.resolve(query);

        std::lock_guard<std::mutex> lock(m_mutex);
        m_remotes.insert(std::make_pair(key, endpoint));

        return endpoint;
    }

public:

    asio_udp_channel(const endpoint& address)
        : m_socket(m_io)
        , m_timer(m_io)
    {
        boost::asio::ip::udp::endpoint endpoint = resolve_endpoint(address.first, std::to_string(address.second));

        m_socket.open(endpoint.protocol());

        static const size_t SOCKET_BUFFER_SIZE = 1048576;

        m_socket.non_blocking(true);
        m_socket.set_option(boost::asio::socket_base::send_buffer_size(SOCKET_BUFFER_SIZE));
        m_socket.set_option(boost::asio::socket_base::receive_buffer_size(SOCKET_BUFFER_SIZE));

        m_socket.bind(endpoint);
    }

    ~asio_udp_channel()
    {
        if (m_socket.is_open())
        {
            boost::system::error_code ec;
            m_socket.shutdown(boost::asio::ip::udp::socket::shutdown_both, ec);
            m_socket.close(ec);
        }
    }

    size_t receive(std::shared_ptr<transfer> data, int64_t timeout) noexcept(false) override
    {
        boost::asio::ip::udp::endpoint endpoint;
        size_t size = exec([&](const async_io_callback_t& callback)
        {
            m_socket.async_receive_from(boost::asio::buffer(data->buffer), endpoint, callback);
        }, timeout);

        data->remote.first = endpoint.address().to_string();
        data->remote.second = endpoint.port();

        _trc_ << data->remote.first << ":" << data->remote.second << " >>>>> " << utils::to_hexadecimal(data->buffer.data(), size);

        if (size == 0)
            throw std::runtime_error("can't receive message");

        return size;
    }

    size_t send(std::shared_ptr<transfer> data, int64_t timeout) noexcept(false) override
    {
        auto endpoint = resolve_endpoint(
            data->remote.first,
            std::to_string(data->remote.second)
            );

        size_t size = exec([&](const async_io_callback_t& callback)
        {
            m_socket.async_send_to(boost::asio::buffer(data->buffer), endpoint, callback);
        }, timeout);

        _trc_ << data->remote.first << ":" << data->remote.second << " <<<<< " << utils::to_hexadecimal(data->buffer.data(), size);

        if (size < data->buffer.size())
            throw std::runtime_error("can't send message");

        return size;
    }
};

std::shared_ptr<udp> create_udp_channel(const endpoint& address)
{
    return std::make_shared<asio_udp_channel>(address);
}

}}
