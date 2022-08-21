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

namespace plexus { namespace network { namespace raw {

template<int proto_id> class asio_raw_transport : public plexus::network::transport
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
        if (proto_id == IPPROTO_ICMP)
        {
            unsigned long flag = 1;
            ioctlsocket(m_socket.native_handle(), SIO_RCVALL, &flag);
        }
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

    void receive(std::shared_ptr<transfer> tran, int64_t timeout) noexcept(false) override
    {
        auto timer = [start = boost::posix_time::microsec_clock::universal_time()]()
        {
            return boost::posix_time::microsec_clock::universal_time() - start;
        };

        auto match = resolve_endpoint(tran->remote);
        while (timer().total_milliseconds() < timeout)
        {
            size_t size = exec([&](const async_io_callback_t& callback)
            {
                m_socket.async_receive(boost::asio::buffer(tran->packet->data(), tran->packet->size()), callback);
            }, timeout - timer().total_milliseconds());

            std::shared_ptr<ip_packet> ip = std::static_pointer_cast<ip_packet>(tran->packet);

            if (ip->total_length() > size)
                throw std::runtime_error("received part of ip packet");

            auto source = get_source_endpoint(ip);
            if (is_matched(source, match))
            {
                _trc_ << source << " >>>>> " << std::make_pair(tran->packet->data(), size);
                return;
            }
        }

        throw boost::system::error_code(boost::asio::error::operation_aborted);
    }

    void send(std::shared_ptr<transfer> tran, int64_t timeout, uint8_t hops) noexcept(false) override
    {
        auto dest = resolve_endpoint(tran->remote);

        size_t size = exec([&](const async_io_callback_t& callback)
        {
            m_socket.set_option(boost::asio::ip::unicast::hops(hops));
            m_socket.async_send_to(boost::asio::buffer(tran->packet->data(), tran->packet->size()), dest, callback);
        }, timeout);

        _trc_ << dest << " <<<<< " << std::make_pair(tran->packet->data(), size);

        if (tran->packet->size() > size)
            throw std::runtime_error("sent part of icmp packet");
    }
};

std::shared_ptr<icmp_packet> icmp_packet::make_ping_packet(uint16_t id, uint16_t seq, const std::vector<uint8_t>& data)
{
    std::shared_ptr<icmp_packet> echo = std::make_shared<icmp_packet>(8 + data.size());

    echo->set_byte(0, icmp_packet::echo_request);
    echo->set_byte(1, 0);
    echo->set_word(4, id);
    echo->set_word(6, seq);

    uint32_t sum = (echo->type() << 8) + echo->code() + echo->identifier() + echo->sequence_number();

    uint8_t* dst = echo->data() + 8;

    for (size_t i = 0; i < data.size(); ++i)
    {
        dst[i] = data[i];

        if (i % 2 == 0)
            sum += dst[i] << 8;
        else
            sum += dst[i];
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    echo->set_word(2, static_cast<uint16_t>(~sum));

    return echo;
}

std::shared_ptr<tcp_packet> tcp_packet::make_syn_packet(uint16_t src_port, uint16_t dst_port, const std::vector<uint8_t>& data)
{
    return 0;
}

std::shared_ptr<udp_packet> udp_packet::make_packet(uint16_t src_port, uint16_t dst_port, const std::vector<uint8_t>& data)
{
    std::shared_ptr<udp_packet> udp = std::make_shared<udp_packet>(8 + data.size());

    udp->set_word(0, src_port);
    udp->set_word(2, dst_port);
    udp->set_word(4, 8 + data.size());

    uint32_t sum = udp->source_port() + udp->dest_port() + udp->length();

    uint8_t* dst = udp->data() + 8;
    for (size_t i = 0; i < data.size(); ++i)
    {
        dst[i] = data[i];

        if (i % 2 == 0)
            sum += dst[i] << 8;
        else
            sum += dst[i];
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    udp->set_word(6, static_cast<uint16_t>(~sum));

    return udp;
}

} // namespace raw

std::shared_ptr<plexus::network::transport> create_icmp_transport(const endpoint& local)
{
    return std::make_shared<raw::asio_raw_transport<IPPROTO_ICMP>>(local);
}

std::shared_ptr<plexus::network::transport> create_tcp_transport(const endpoint& local)
{
    return std::make_shared<raw::asio_raw_transport<IPPROTO_TCP>>(local);
}

std::shared_ptr<plexus::network::transport> create_udp_transport(const endpoint& local)
{
    return std::make_shared<raw::asio_raw_transport<IPPROTO_UDP>>(local);
}

}}
