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
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/deadline_timer.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include "network.h"
#include "utils.h"
#include "log.h"


namespace plexus { namespace network {

class asio_udp_channel : public transport
{
    typedef std::map<endpoint, boost::asio::ip::udp::endpoint> endpoint_cache_t;
    typedef std::function<void(const boost::system::error_code&, size_t)> async_io_callback_t;
    typedef std::function<void(const async_io_callback_t&)> async_io_call_t;

    boost::asio::io_service      m_io;
    boost::asio::ip::udp::socket m_socket;
    boost::asio::deadline_timer  m_timer;
    endpoint_cache_t             m_endpoints;

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

    boost::asio::ip::udp::endpoint resolve_endpoint(const endpoint& ep)
    {
        if (ep.first.empty())
        {
            return boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), ep.second);
        }

        auto iter = m_endpoints.find(ep);
        if (iter != m_endpoints.end())
            return iter->second;

        boost::asio::ip::udp::resolver resolver(m_io);
        boost::asio::ip::udp::resolver::query query(boost::asio::ip::udp::v4(), ep.first, std::to_string(ep.second));
        boost::asio::ip::udp::endpoint endpoint = *resolver.resolve(query);

        m_endpoints.insert(std::make_pair(ep, endpoint));

        return endpoint;
    }

    static bool is_matched(const boost::asio::ip::udp::endpoint& source, const boost::asio::ip::udp::endpoint& match)
    {
        return (match.address().is_unspecified() || match.address() == source.address()) && (match.port() == 0 || match.port() == source.port());
    }

public:

    asio_udp_channel(const endpoint& bind)
        : m_socket(m_io)
        , m_timer(m_io)
    {
        boost::asio::ip::udp::endpoint endpoint = resolve_endpoint(bind);

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

    void receive(const endpoint& remote, std::shared_ptr<buffer> buf, int64_t timeout) noexcept(false) override
    {
        auto timer = [start = boost::posix_time::microsec_clock::universal_time()]()
        {
            return boost::posix_time::microsec_clock::universal_time() - start;
        };

        auto match = resolve_endpoint(remote);
        while (timer().total_milliseconds() < timeout)
        {
            boost::asio::ip::udp::endpoint source;
            size_t size = exec([&](const async_io_callback_t& callback)
            {
                m_socket.async_receive_from(boost::asio::buffer(buf->data(), buf->size()), source, callback);
            }, timeout);

            if (is_matched(source, match))
            {
                _trc_ << source << " >>>>> " << std::make_pair(buf->data(), size);

                buf->move_tail(buf->size() - size, true);
                return;
            }
        }

        throw boost::system::error_code(boost::asio::error::operation_aborted);
    }

    void send(const endpoint& remote, std::shared_ptr<buffer> buf, int64_t timeout, uint8_t hops) noexcept(false) override
    {
        auto endpoint = resolve_endpoint(remote);

        size_t size = exec([&](const async_io_callback_t& callback)
        {
            m_socket.set_option(boost::asio::ip::unicast::hops(hops));
            m_socket.async_send_to(boost::asio::buffer(buf->data(), buf->size()), endpoint, callback);
        }, timeout);

        _trc_ << endpoint << " <<<<< " << std::make_pair(buf->data(), size);

        if (size < buf->size())
            throw std::runtime_error("can't send message");
    }
};

std::shared_ptr<transport> create_udp_transport(const endpoint& bind)
{
    return std::make_shared<asio_udp_channel>(bind);
}

}}
