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

#include <vector>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/shared_array.hpp>

namespace plexus { namespace network {

typedef std::string address;
typedef uint16_t port;
typedef std::pair<address, port> endpoint;

class packet
{
    boost::shared_array<uint8_t> m_buffer;
    std::vector<size_t> m_slices;
    size_t m_length;

    packet(boost::shared_array<uint8_t> buffer, size_t length, const std::vector<size_t>& slices) 
        : m_buffer(buffer)
        , m_slices(slices)
        , m_length(length)
    {
    }

    size_t head() const { return m_slices.empty() ? 0 : m_slices.back(); }

public:

    packet(size_t length)
        : m_buffer(new uint8_t[length])
        , m_length(length)
    {
        std::memset(m_buffer.get(), 0, length);
    }

    packet(const packet& other)
        : m_buffer(other.m_buffer)
        , m_slices(other.m_slices)
        , m_length(other.m_length)
    {
    }

    uint8_t* data()
    {
        return m_buffer.get() + head();
    }

    const uint8_t* data() const
    {
        return m_buffer.get() + head();
    }

    size_t size() const
    {
        return m_length - head();
    }

    uint8_t byte(size_t p) const
    {
        size_t pos = head() + p;
        if (pos >= m_length)
            throw std::out_of_range("position is out of range");

        return m_buffer[pos];
    }

    uint16_t word(uint8_t u, uint8_t l) const
    {
        size_t upos = head() + u;
        size_t lpos = head() + l;

        if (upos >= m_length || lpos >= m_length)
            throw std::out_of_range("position is out of range");

        return uint16_t(m_buffer[upos] << 8) + m_buffer[lpos];
    }

    packet pop_head(size_t size) const
    {
        size_t slice = head() + size;
        if (slice >= m_length)
            throw std::out_of_range("offset is out of range");

        std::vector<size_t> slices = m_slices;
        slices.push_back(slice);
        return packet(m_buffer, m_length, slices);
    }

    packet push_head() const
    {
        if (m_slices.empty())
            throw std::runtime_error("no slice to make cover");

        std::vector<size_t> slices = m_slices;
        slices.pop_back();
        return packet(m_buffer, m_length, slices);
    }
};

struct ip_packet : public packet
{
    ip_packet(const packet& pack) : packet(pack) { }

    uint8_t version() const { return (byte(0) >> 4) & 0xF; }
    uint16_t header_length() const { return (byte(0) & 0xF) * 4; }
    uint8_t type_of_service() const { return byte(1); }
    uint16_t total_length() const { return word(2, 3); }
    uint16_t identification() const { return word(4, 5);  }
    uint16_t fragment_offset() const { return word(6, 7) & 0x1FFF; }
    uint8_t time_to_live() const { return byte(8); }
    uint8_t protocol() const { return byte(9); }
    uint16_t header_checksum() const { return word(10, 11); }
    bool dont_fragment() const { return (byte(6) & 0x40) != 0; }
    bool more_fragments() const { return (byte(6) & 0x20) != 0; }
    boost::asio::ip::address_v4 source_address() const { return boost::asio::ip::address_v4({byte(12), byte(13), byte(14), byte(15)}); }
    boost::asio::ip::address_v4 destination_address() const { return boost::asio::ip::address_v4({byte(16), byte(17), byte(18), byte(19)}); }
    template<class packet_t> std::shared_ptr<packet_t> envelope() const { return std::make_shared<packet_t>(packet::push_head()); }
    template<class packet_t> std::shared_ptr<packet_t> payload() const { return std::make_shared<packet_t>(packet::pop_head(header_length())); }
};

struct icmp_packet : public packet
{
    enum type
    {
        echo_reply = 0,
        destination_unreachable = 3,
        source_quench = 4,
        redirect = 5,
        echo_request = 8,
        time_exceeded = 11,
        parameter_problem = 12,
        timestamp_request = 13,
        timestamp_reply = 14,
        info_request = 15,
        info_reply = 16,
        address_request = 17,
        address_reply = 18
    };

    icmp_packet(const packet& pack) : packet(pack) { }

    uint8_t type() const { return byte(0); }
    uint8_t code() const { return byte(1); }
    uint16_t checksum() const { return word(2, 3); }
    uint16_t identifier() const { return word(4, 5); }
    uint16_t sequence_number() const { return word(6, 7); }
    uint8_t pointer() const { return byte(4); }
    uint16_t mtu() const { return word(6, 7); }
    boost::asio::ip::address_v4 gateway() const { return boost::asio::ip::address_v4({byte(4), byte(5), byte(6), byte(7)}); }
    template<class packet_t> std::shared_ptr<packet_t> envelope() const { return std::make_shared<packet_t>(packet::push_head()); }
    template<class packet_t> std::shared_ptr<packet_t> payload() const { return std::make_shared<packet_t>(packet::pop_head(8)); }
};

struct udp_packet : public packet
{
    udp_packet(const packet& pack) : packet(pack) { }

    uint16_t source_port() const { return word(0, 1); }
    uint16_t dest_port() const { return word(2, 3); }
    uint16_t length() const { return word(4, 5); }
    uint16_t checksum() const { return word(6, 7); }
    template<class packet_t> std::shared_ptr<packet_t> envelope() const { return std::make_shared<packet_t>(packet::push_head()); }
    template<class packet_t> std::shared_ptr<packet_t> payload() const { return std::make_shared<packet_t>(packet::pop_head(8)); }
};

}}
