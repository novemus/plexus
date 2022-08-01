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

class buffer
{
    boost::shared_array<uint8_t> m_buffer;
    std::vector<size_t> m_slices;
    size_t m_length;

    buffer(boost::shared_array<uint8_t> buffer, size_t length, const std::vector<size_t>& slices) 
        : m_buffer(buffer)
        , m_slices(slices)
        , m_length(length)
    {
    }

    size_t head() const { return m_slices.empty() ? 0 : m_slices.back(); }

public:

    buffer(size_t length)
        : m_buffer(new uint8_t[length])
        , m_length(length)
    {
        std::memset(m_buffer.get(), 0, length);
    }

    buffer(const std::string& data)
        : m_buffer(new uint8_t[data.size()])
        , m_length(data.size())
    {
        std::memcpy(m_buffer.get(), data.data(), data.size());
    }

    buffer(const buffer& other)
        : m_buffer(other.m_buffer)
        , m_slices(other.m_slices)
        , m_length(other.m_length)
    {
    }

    virtual ~buffer() {}

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

    void set_byte(size_t p, uint8_t val)
    {
        size_t pos = head() + p;
        if (pos >= m_length)
            throw std::out_of_range("position is out of range");

        m_buffer[pos] = val;
    }

    uint8_t get_byte(size_t p) const
    {
        size_t pos = head() + p;
        if (pos >= m_length)
            throw std::out_of_range("position is out of range");

        return m_buffer[pos];
    }

    uint16_t get_word(uint8_t u, uint8_t l) const
    {
        size_t upos = head() + u;
        size_t lpos = head() + l;

        if (upos >= m_length || lpos >= m_length)
            throw std::out_of_range("position is out of range");

        return uint16_t(m_buffer[upos] << 8) + m_buffer[lpos];
    }

    void set_word(int8_t u, uint8_t l, uint16_t val) const
    {
        size_t upos = head() + u;
        size_t lpos = head() + l;

        if (upos >= m_length || lpos >= m_length)
            throw std::out_of_range("position is out of range");

        m_buffer[upos] = val >> 8;
        m_buffer[lpos] = val & 0xFF;
    }

    buffer pop_head(size_t size) const
    {
        size_t slice = head() + size;
        if (slice >= m_length)
            throw std::out_of_range("offset is out of range");

        std::vector<size_t> slices = m_slices;
        slices.push_back(slice);
        return buffer(m_buffer, m_length, slices);
    }

    buffer push_head() const
    {
        if (m_slices.empty())
            throw std::runtime_error("no slice to make cover");

        std::vector<size_t> slices = m_slices;
        slices.pop_back();
        return buffer(m_buffer, m_length, slices);
    }
};

struct ip_packet : public buffer
{
    ip_packet(size_t len) : buffer(len) { }
    ip_packet(const buffer& buf) : buffer(buf) { }

    uint8_t version() const { return (get_byte(0) >> 4) & 0xF; }
    uint16_t header_length() const { return (get_byte(0) & 0xF) * 4; }
    uint8_t type_of_service() const { return get_byte(1); }
    uint16_t total_length() const { return get_word(2, 3); }
    uint16_t identification() const { return get_word(4, 5);  }
    uint16_t fragment_offset() const { return get_word(6, 7) & 0x1FFF; }
    uint8_t time_to_live() const { return get_byte(8); }
    uint8_t protocol() const { return get_byte(9); }
    uint16_t header_checksum() const { return get_word(10, 11); }
    bool dont_fragment() const { return (get_byte(6) & 0x40) != 0; }
    bool more_fragments() const { return (get_byte(6) & 0x20) != 0; }
    boost::asio::ip::address_v4 source_address() const { return boost::asio::ip::address_v4({get_byte(12), get_byte(13), get_byte(14), get_byte(15)}); }
    boost::asio::ip::address_v4 destination_address() const { return boost::asio::ip::address_v4({get_byte(16), get_byte(17), get_byte(18), get_byte(19)}); }
    template<class packet_t> std::shared_ptr<packet_t> envelope() const { return std::make_shared<packet_t>(buffer::push_head()); }
    template<class packet_t> std::shared_ptr<packet_t> payload() const { return std::make_shared<packet_t>(buffer::pop_head(header_length())); }
};

struct icmp_packet : public buffer
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

    icmp_packet(size_t len) : buffer(len) { }
    icmp_packet(const buffer& buf) : buffer(buf) { }

    uint8_t type() const { return get_byte(0); }
    uint8_t code() const { return get_byte(1); }
    uint16_t checksum() const { return get_word(2, 3); }
    uint16_t identifier() const { return get_word(4, 5); }
    uint16_t sequence_number() const { return get_word(6, 7); }
    uint8_t pointer() const { return get_byte(4); }
    uint16_t mtu() const { return get_word(6, 7); }
    boost::asio::ip::address_v4 gateway() const { return boost::asio::ip::address_v4({get_byte(4), get_byte(5), get_byte(6), get_byte(7)}); }
    template<class packet_t> std::shared_ptr<packet_t> envelope() const { return std::make_shared<packet_t>(buffer::push_head()); }
    template<class packet_t> std::shared_ptr<packet_t> payload() const { return std::make_shared<packet_t>(buffer::pop_head(8)); }

    static std::shared_ptr<icmp_packet> make_ping_packet(uint16_t id, uint16_t seq, const std::string& data = "plexus");
};

struct udp_packet : public buffer
{
    udp_packet(const buffer& buf) : buffer(buf) { }

    uint16_t source_port() const { return get_word(0, 1); }
    uint16_t dest_port() const { return get_word(2, 3); }
    uint16_t length() const { return get_word(4, 5); }
    uint16_t checksum() const { return get_word(6, 7); }
    template<class packet_t> std::shared_ptr<packet_t> envelope() const { return std::make_shared<packet_t>(buffer::push_head()); }
    template<class packet_t> std::shared_ptr<packet_t> payload() const { return std::make_shared<packet_t>(buffer::pop_head(8)); }
};

}}
