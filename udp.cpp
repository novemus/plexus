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
#include <map>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/udp.hpp>

namespace plexus { namespace network {

class asio_udp_channel : public transport
{
    boost::asio::io_service                            m_io;
    asio_socket<boost::asio::ip::udp::socket>          m_socket;
    std::map<endpoint, boost::asio::ip::udp::endpoint> m_endpoints;

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
            size_t size = m_socket.receive_from(boost::asio::buffer(buf->data(), buf->size()), source, boost::posix_time::milliseconds(timeout));

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

        m_socket.set_option(boost::asio::ip::unicast::hops(hops));
        size_t size = m_socket.send_to(boost::asio::buffer(buf->data(), buf->size()), endpoint, boost::posix_time::milliseconds(timeout));

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
