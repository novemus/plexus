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
#include <boost/asio/deadline_timer.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include "network.h"
#include "utils.h"
#include "log.h"


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
    std::mutex                    m_mutex;

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
        {
            std::lock_guard<std::mutex> lock(m_mutex);

            auto iter = m_remotes.find(ip);
            if (iter != m_remotes.end())
                return iter->second;
        }

        boost::asio::ip::icmp::resolver resolver(m_io);
        boost::asio::ip::icmp::resolver::query query(boost::asio::ip::icmp::v4(), ip, "");
        boost::asio::ip::icmp::endpoint endpoint = *resolver.resolve(query);

        std::lock_guard<std::mutex> lock(m_mutex);
        m_remotes.insert(std::make_pair(ip, endpoint));

        return endpoint;
    }

public:

    asio_icmp_channel(const address& local)
        : m_socket(m_io)
        , m_timer(m_io)
    {
        boost::asio::ip::icmp::endpoint endpoint = resolve_endpoint(local);

        m_socket.open(endpoint.protocol());
        m_socket.non_blocking(true);
        m_socket.bind(endpoint);
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
            m_socket.async_receive(boost::asio::buffer(pack->data(), pack->total_length()), callback);
        }, timeout);

        _trc_ << pack->source_address().to_string() << ":icmp >>>>> " << utils::to_hexadecimal(pack->data(), size);

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

std::shared_ptr<icmp_packet> make_echo_packet(uint8_t type, uint16_t id, uint16_t seq, std::shared_ptr<buffer> data)
{
    std::shared_ptr<icmp_packet> echo = std::make_shared<icmp_packet>(buffer(8 + data->size()));

    echo->set_byte(0, type);
    echo->set_byte(1, 0);
    echo->set_word(4, 5, id);
    echo->set_word(6, 7, seq);

    unsigned int sum = (echo->type() << 8) + echo->code() + echo->identifier() + echo->sequence_number();

    uint8_t* src = data->data();
    uint8_t* dst = echo->data() + 8;

    for (size_t i = 0; i < data->size(); i += 2)
    {
        dst[i] = src[i];
        dst[i + 1] = src[i + 1];
        sum += dst[i] << 8;
        sum += dst[i + 1];
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    echo->set_word(2, 3, sum);
}

}}
