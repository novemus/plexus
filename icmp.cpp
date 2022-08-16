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
#include <boost/asio/deadline_timer.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include "network.h"
#include "utils.h"
#include "log.h"

#ifdef _WIN32
#include <mstcpip.h>
#endif

namespace plexus { namespace network {

class asio_icmp_channel : public icmp, public std::enable_shared_from_this<asio_icmp_channel>
{
    typedef std::map<address, boost::asio::ip::icmp::endpoint> endpoint_cache_t;
    typedef std::function<void(const boost::system::error_code&, size_t)> async_io_callback_t;
    typedef std::function<void(const async_io_callback_t&)> async_io_call_t;

    boost::asio::io_service       m_io;
    boost::asio::ip::icmp::socket m_socket;
    boost::asio::deadline_timer   m_timer;
    endpoint_cache_t              m_remotes;

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

    boost::asio::ip::icmp::endpoint resolve_endpoint(const address& ip)
    {
        auto iter = m_remotes.find(ip);
        if (iter != m_remotes.end())
            return iter->second;

        boost::asio::ip::icmp::resolver resolver(m_io);
        boost::asio::ip::icmp::resolver::query query(boost::asio::ip::icmp::v4(), ip, "");
        boost::asio::ip::icmp::endpoint endpoint = *resolver.resolve(query);

        m_remotes.insert(std::make_pair(ip, endpoint));

        return endpoint;
    }

public:

    asio_icmp_channel(const address& local)
        : m_socket(m_io, boost::asio::ip::icmp::v4())
        , m_timer(m_io)
    {
        m_socket.non_blocking(true);
        if (local.empty())
            m_socket.bind(boost::asio::ip::icmp::endpoint(boost::asio::ip::icmp::v4(), 0));
        else
            m_socket.bind(resolve_endpoint(local));

#ifdef _WIN32
        unsigned long flag = 1;
        ioctlsocket(m_socket.native_handle(), SIO_RCVALL, &flag);
#endif
    }

    ~asio_icmp_channel()
    {
        if (m_socket.is_open())
        {
            boost::system::error_code ec;
            m_socket.shutdown(boost::asio::ip::icmp::socket::shutdown_both, ec);
            m_socket.close(ec);
        }
    }

    void receive(std::shared_ptr<transfer> tran, int64_t timeout) noexcept(false) override
    {
        std::shared_ptr<ip_packet> pack = std::dynamic_pointer_cast<ip_packet>(tran->packet);
        size_t size = exec([&](const async_io_callback_t& callback)
        {
            m_socket.async_receive(boost::asio::buffer(pack->data(), pack->size()), callback);
        }, timeout);

        tran->remote = pack->source_address().to_string();

        _trc_ << tran->remote << ":icmp >>>>> " << utils::to_hexadecimal(pack->data(), size);

        if (pack->total_length() > size)
            throw std::runtime_error("received part of ip packet");
    }

    void send(std::shared_ptr<transfer> tran, int64_t timeout, uint8_t hops) noexcept(false) override
    {
        std::shared_ptr<icmp_packet> pack = std::dynamic_pointer_cast<icmp_packet>(tran->packet);
        auto endpoint = resolve_endpoint(tran->remote);

        size_t size = exec([&](const async_io_callback_t& callback)
        {
            m_socket.set_option(boost::asio::ip::unicast::hops(hops));
            m_socket.async_send_to(boost::asio::buffer(pack->data(), pack->size()), endpoint, callback);
        }, timeout);

        _trc_ << tran->remote << ":icmp <<<<< " << utils::to_hexadecimal(pack->data(), size);

        if (pack->size() > size)
            throw std::runtime_error("sent part of icmp packet");
    }
};

std::shared_ptr<icmp> create_icmp_channel(const address& local)
{
    return std::make_shared<asio_icmp_channel>(local);
}

std::shared_ptr<icmp_packet> icmp_packet::make_ping_packet(uint16_t id, uint16_t seq, const std::string& data)
{
    std::shared_ptr<icmp_packet> echo = std::make_shared<icmp_packet>(8 + data.size());

    echo->set_byte(0, icmp_packet::echo_request);
    echo->set_byte(1, 0);
    echo->set_word(4, 5, id);
    echo->set_word(6, 7, seq);

    uint32_t sum = (echo->type() << 8) + echo->code() + echo->identifier() + echo->sequence_number();

    uint8_t* dst = echo->data() + 8;

    for (size_t i = 0; i < data.size(); ++i)
    {
        dst[i] = static_cast<uint8_t>(data[i]);

        if (i % 2 == 0)
            sum += dst[i] << 8;
        else
            sum += dst[i];
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    echo->set_word(2, 3, static_cast<uint16_t>(~sum));

    return echo;
}

}}