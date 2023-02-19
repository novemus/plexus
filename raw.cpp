/*
 * Copyright (c) 2022 Novemus Band. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 */

#include "network.h"
#include "utils.h"
#include <logger.h>
#include <map>
#include <iostream>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/deadline_timer.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>

#ifdef _WIN32
#include <mstcpip.h>
#endif

namespace plexus { namespace network { namespace raw {

template<int proto_id> class asio_raw_transport : public transport
{
    typedef plexus::network::raw::proto<proto_id> proto;
    typedef std::function<void(const boost::system::error_code&, size_t)> async_io_callback_t;
    typedef std::function<void(const async_io_callback_t&)> async_io_call_t;

    boost::asio::io_service                      m_io;
    typename proto::socket                       m_socket;
    boost::asio::deadline_timer                  m_timer;
    std::map<endpoint, typename proto::endpoint> m_endpoints;

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

    typename proto::endpoint resolve_endpoint(const endpoint& ep)
    {
        uint16_t port = proto_id == IPPROTO_ICMP ? 0 : ep.second;

        if (ep.first.empty())
        {
            return typename proto::endpoint(proto::v4(), port);
        }

        auto iter = m_endpoints.find(ep);

        if (iter == m_endpoints.end())
        {
            typename proto::resolver resolver(m_io);
            typename proto::resolver::query query(proto::v4(), ep.first, "");
            iter = m_endpoints.insert(
                std::make_pair(ep, typename proto::endpoint(resolver.resolve(query)->endpoint().address(), port))
                ).first;
        }

        return iter->second;
    }

    static typename proto::endpoint get_source_endpoint(std::shared_ptr<ip_packet> ip)
    {
        if (ip->protocol() == IPPROTO_UDP)
        {
            auto udp = ip->payload<udp_packet>();
            return typename proto::endpoint(ip->source_address(), udp->source_port());
        }
        else if (ip->protocol() == IPPROTO_TCP)
        {
            auto tcp = ip->payload<tcp_packet>();
            return typename proto::endpoint(ip->source_address(), tcp->source_port());
        }

        return typename proto::endpoint(ip->source_address(), 0);
    }

    static bool is_matched(const typename proto::endpoint& source, const typename proto::endpoint& match)
    {
        return (match.address().is_unspecified() || match.address() == source.address()) && (match.port() == 0 || match.port() == source.port());
    }

public:

    asio_raw_transport(const endpoint& local)
        : m_socket(m_io, proto::v4())
        , m_timer(m_io)
    {
        m_socket.non_blocking(true);
        m_socket.bind(resolve_endpoint(local));

#ifdef _WIN32
        unsigned long flag = 1;
        ioctlsocket(m_socket.native_handle(), SIO_RCVALL, &flag);
#endif
    }

    ~asio_raw_transport()
    {
        if (m_socket.is_open())
        {
            boost::system::error_code ec;
            m_socket.shutdown(proto::socket::shutdown_both, ec);
            m_socket.close(ec);
        }
    }

    void receive(const endpoint& remote, std::shared_ptr<buffer> buffer, int64_t timeout) noexcept(false) override
    {
        if (buffer->size() < 20)
            throw std::runtime_error("buffer too small for ip packet");

        auto timer = [start = boost::posix_time::microsec_clock::universal_time()]()
        {
            return boost::posix_time::microsec_clock::universal_time() - start;
        };

        auto match = resolve_endpoint(remote);
        while (timer().total_milliseconds() < timeout)
        {
            size_t size = exec([&](const async_io_callback_t& callback)
            {
                m_socket.async_receive(boost::asio::buffer(buffer->data(), buffer->size()), callback);
            }, timeout - timer().total_milliseconds());

            std::shared_ptr<ip_packet> ip = std::static_pointer_cast<ip_packet>(buffer);

            auto source = get_source_endpoint(ip);
            if (is_matched(source, match))
            {
                if (ip->total_length() > buffer->size())
                    throw std::runtime_error("buffer too small for received packet");

                _trc_ << source << " >>>>> " << std::make_pair(buffer->data(), size);

                buffer->move_tail(buffer->size() - size, true);
                return;
            }
        }

        throw boost::system::error_code(boost::asio::error::operation_aborted);
    }

    void send(const endpoint& remote, std::shared_ptr<buffer> buffer, int64_t timeout, uint8_t hops) noexcept(false) override
    {
        auto dest = resolve_endpoint(remote);

        size_t size = exec([&](const async_io_callback_t& callback)
        {
            m_socket.set_option(boost::asio::ip::unicast::hops(hops));
            m_socket.async_send_to(boost::asio::buffer(buffer->data(), buffer->size()), dest, callback);
        }, timeout);

        _trc_ << dest << " <<<<< " << std::make_pair(buffer->data(), size);

        if (buffer->size() > size)
            throw std::runtime_error("sent part of icmp packet");
    }
};

uint16_t calc_checksum(std::shared_ptr<buffer> data)
{
    uint16_t* ptr = (uint16_t*)data->data();
    size_t count = data->size();
    uint32_t sum = 0;

    while (count > 1)  
    {
        sum += ntohs(*(uint16_t*)ptr++);
        count -= 2;
    }  

    if(count > 0)
    {
        uint16_t tail = *(uint8_t*)ptr;
        sum += ntohs(tail);
    }  

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return static_cast<uint16_t>(~sum);
}

std::shared_ptr<icmp_packet> icmp_packet::make_ping_packet(uint16_t id, uint16_t seq, std::shared_ptr<buffer> data)
{
    std::shared_ptr<icmp_packet> echo = std::make_shared<icmp_packet>(data->pop_head(8));

    echo->set_byte(0, icmp_packet::echo_request);
    echo->set_byte(1, 0);
    echo->set_word(2, 0);
    echo->set_word(4, htons(id));
    echo->set_word(6, htons(seq));
    echo->set_word(2, calc_checksum(echo));

    return echo;
}

std::shared_ptr<tcp_packet> tcp_packet::make_syn_packet(const endpoint& src, const endpoint& dst, std::shared_ptr<buffer> data)
{
    std::shared_ptr<tcp_packet> tcp = std::make_shared<tcp_packet>(data->pop_head(40));

    tcp->set_word(0, src.second);
    tcp->set_word(2, dst.second);
    tcp->set_dword(4, 0);
    tcp->set_dword(8, 0);
    tcp->set_byte(12, 0xa0);
    tcp->set_byte(13, (uint8_t)flag::syn);
    tcp->set_word(14, 5840);
    tcp->set_word(16, 0);
    tcp->set_word(18, 0);

    // MSS option
    tcp->set_byte(20, 2);
    tcp->set_byte(21, 4);
    tcp->set_word(22, 1460);

    // SACK option
    tcp->set_byte(24, 4);
    tcp->set_byte(25, 2);

    // Timestamps option
    tcp->set_byte(26, 8);
    tcp->set_byte(27, 10);
    tcp->set_dword(28, utils::random<uint32_t>());
    tcp->set_dword(32, 0);

    // No-Operation option
    tcp->set_byte(36, 1);

    // Window scale option
    tcp->set_byte(37, 3);
    tcp->set_byte(38, 3);
    tcp->set_byte(39, 7);

    boost::asio::ip::address_v4 from =  boost::asio::ip::make_address_v4(src.first);
    boost::asio::ip::address_v4 to = boost::asio::ip::make_address_v4(dst.first);

    std::shared_ptr<buffer> pseudo = std::make_shared<buffer>(tcp->pop_head(12));

    pseudo->set_dword(0, from.to_uint());              // source address
    pseudo->set_dword(4, to.to_uint());                // destination address
    pseudo->set_byte(8, 0);                            // placeholder
    pseudo->set_byte(9, IPPROTO_TCP);                  // protocol
    pseudo->set_word(10, 40 + (uint16_t)data->size()); // tcp length

    tcp->set_word(16, calc_checksum(pseudo));

    return tcp;
}

std::shared_ptr<udp_packet> udp_packet::make_packet(const endpoint& src, const endpoint& dst, std::shared_ptr<buffer> data)
{
    std::shared_ptr<udp_packet> udp = std::make_shared<udp_packet>(data->pop_head(8));

    udp->set_word(0, src.second);
    udp->set_word(2, dst.second);
    udp->set_word(4, (uint16_t)udp->size());
    udp->set_word(6, 0);

    boost::asio::ip::address_v4 from =  boost::asio::ip::make_address_v4(src.first);
    boost::asio::ip::address_v4 to = boost::asio::ip::make_address_v4(dst.first);

    std::shared_ptr<buffer> pseudo = std::make_shared<buffer>(udp->pop_head(12));

    pseudo->set_dword(0, from.to_uint());              // source address
    pseudo->set_dword(4, to.to_uint());                // destination address
    pseudo->set_byte(8, 0);                            // placeholder
    pseudo->set_byte(9, IPPROTO_UDP);                  // protocol
    pseudo->set_word(10, 8 + (uint16_t)data->size());  // udp length

    udp->set_word(6, calc_checksum(pseudo));

    return udp;
}

std::shared_ptr<transport> create_icmp_transport(const endpoint& local)
{
    return std::make_shared<raw::asio_raw_transport<IPPROTO_ICMP>>(local);
}

std::shared_ptr<transport> create_tcp_transport(const endpoint& local)
{
    return std::make_shared<raw::asio_raw_transport<IPPROTO_TCP>>(local);
}

std::shared_ptr<transport> create_udp_transport(const endpoint& local)
{
    return std::make_shared<raw::asio_raw_transport<IPPROTO_UDP>>(local);
}

}}}
