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
#include <boost/asio/ip/udp.hpp>

namespace plexus { namespace network {

class asio_udp_channel : public udp
{
    boost::asio::io_service                   m_io;
    asio_socket<boost::asio::ip::udp::socket> m_socket;

    static bool is_matched(const boost::asio::ip::udp::endpoint& source, const boost::asio::ip::udp::endpoint& match)
    {
        return (match.address().is_unspecified() || match.address() == source.address()) && (match.port() == 0 || match.port() == source.port());
    }

public:

    asio_udp_channel(const boost::asio::ip::udp::endpoint& bind)
        : m_socket(m_io)
    {
        m_socket.open(bind.protocol());

        static const size_t SOCKET_BUFFER_SIZE = 1048576;

        m_socket.non_blocking(true);
        m_socket.set_option(boost::asio::socket_base::send_buffer_size(SOCKET_BUFFER_SIZE));
        m_socket.set_option(boost::asio::socket_base::receive_buffer_size(SOCKET_BUFFER_SIZE));

        if (bind.port())
            m_socket.bind(bind);
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

    size_t receive(const boost::asio::ip::udp::endpoint& remote, const tubus::mutable_buffer& buffer, int64_t timeout) noexcept(false) override
    {
        auto timer = [start = boost::posix_time::microsec_clock::universal_time()]()
        {
            return boost::posix_time::microsec_clock::universal_time() - start;
        };

        while (timer().total_milliseconds() < timeout)
        {
            boost::asio::ip::udp::endpoint source;
            size_t size = m_socket.receive_from(buffer, source, boost::posix_time::milliseconds(timeout));

            if (is_matched(source, remote))
            {
                _trc_ << source << " >>>>> " << std::make_pair(buffer.data(), size);
                return size;
            }
        }

        throw boost::system::error_code(boost::asio::error::operation_aborted);
    }

    size_t send(const boost::asio::ip::udp::endpoint& remote, const tubus::const_buffer& buffer, int64_t timeout, uint8_t hops) noexcept(false) override
    {
        m_socket.set_option(boost::asio::ip::unicast::hops(hops));
        size_t size = m_socket.send_to(buffer, remote, boost::posix_time::milliseconds(timeout));

        _trc_ << remote << " <<<<< " << std::make_pair(buffer.data(), size);

        if (size < buffer.size())
            throw std::runtime_error("can't send message");

        return size;
    }
};

std::shared_ptr<udp> create_udp_transport(const boost::asio::ip::udp::endpoint& bind)
{
    return std::make_shared<asio_udp_channel>(bind);
}

}}
