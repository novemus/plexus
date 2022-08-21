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
#include <boost/asio/detail/socket_types.hpp>
#include <boost/asio/basic_raw_socket.hpp>
#include <boost/asio/ip/basic_endpoint.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/basic_resolver.hpp>
#include <boost/shared_array.hpp>

namespace plexus { namespace network { 

typedef std::pair<std::string, uint16_t> endpoint;
typedef std::pair<boost::shared_array<uint8_t>, size_t> byte_array;

class buffer
{
    byte_array m_buffer;
    std::vector<size_t> m_heads;
    std::vector<size_t> m_tails;

    buffer(const byte_array& buffer, const std::vector<size_t>& heads, const std::vector<size_t>& tails) 
        : m_buffer(buffer)
        , m_heads(heads)
        , m_tails(tails)
    {
    }

    size_t head() const { return m_heads.empty() ? 0 : m_heads.back(); }
    size_t tail() const { return m_tails.empty() ? m_buffer.second : m_tails.back(); }

public:

    buffer(size_t length) : m_buffer(boost::shared_array<uint8_t>(new uint8_t[length]), length)
    {
        std::memset(m_buffer.first.get(), 0, length);
    }

    buffer(const char* data) : m_buffer(boost::shared_array<uint8_t>(new uint8_t[std::strlen(data)]), std::strlen(data))
    {
        std::memcpy(m_buffer.first.get(), data, std::strlen(data));
    }
    
    buffer(const std::vector<uint8_t>& data) : m_buffer(boost::shared_array<uint8_t>(new uint8_t[data.size()]), data.size())
    {
        std::memcpy(m_buffer.first.get(), data.data(), data.size());
    }

    buffer(const buffer& other)
        : m_buffer(other.m_buffer)
        , m_heads(other.m_heads)
        , m_tails(other.m_tails)
    {
    }

    virtual ~buffer() {}

    uint8_t* data()
    {
        return m_buffer.first.get() + head();
    }

    const uint8_t* data() const
    {
        return m_buffer.first.get() + head();
    }

    size_t size() const
    {
        return tail() - head();
    }

    void set_byte(size_t pos, uint8_t val)
    {
        size_t p = head() + pos;
        if (p >= tail())
            throw std::out_of_range("position is out of range");

        m_buffer.first[p] = val;
    }

    uint8_t get_byte(size_t pos) const
    {
        size_t p = head() + pos;
        if (p >= tail())
            throw std::out_of_range("position is out of range");

        return m_buffer.first[p];
    }

    void set_word(size_t pos, uint16_t val)
    {
        size_t p = head() + pos;

        if (p + sizeof(uint16_t) > tail())
            throw std::out_of_range("position is out of range");

        *(uint16_t*)(m_buffer.first.get() + p) = htons(val);
    }

    uint16_t get_word(size_t pos) const
    {
        size_t p = head() + pos;

        if (p + sizeof(uint16_t) > tail())
            throw std::out_of_range("position is out of range");

        return ntohs(*(uint16_t*)(m_buffer.first.get() + p));
    }

    void set_dword(size_t pos, uint32_t val)
    {
        size_t p = head() + pos;

        if (p + sizeof(uint32_t) > tail())
            throw std::out_of_range("position is out of range");

        *(uint32_t*)(m_buffer.first.get() + pos) = htonl(val);
    }

    uint32_t get_dword(size_t pos) const
    {
        size_t p = head() + pos;

        if (p + sizeof(uint32_t) > tail())
            throw std::out_of_range("position is out of range");

        return ntohl(*(uint32_t*)(m_buffer.first.get() + p));
    }

    buffer pop_head(size_t size) const
    {
        size_t h = head() + size;
        if (h > tail())
            throw std::out_of_range("offset is out of range");

        std::vector<size_t> heads = m_heads;
        heads.push_back(h);
        return buffer(m_buffer, heads, m_tails);
    }

    buffer push_head() const
    {
        if (m_heads.empty())
            throw std::runtime_error("no head to push");

        std::vector<size_t> heads = m_heads;
        heads.pop_back();
        return buffer(m_buffer, heads, m_tails);
    }

    buffer pop_tail(size_t size) const
    {
        if (size > tail())
            throw std::runtime_error("offset is out of range");

        std::vector<size_t> tails = m_tails;
        tails.push_back(tail() - size);
        return buffer(m_buffer, m_heads, tails);
    }

    buffer push_tail() const
    {
        if (m_heads.empty())
            throw std::runtime_error("no tail to push");

        std::vector<size_t> tails = m_tails;
        tails.pop_back();
        return buffer(m_buffer, m_heads, tails);
    }
};

namespace raw {

template<int id> class proto
{
    int m_protocol;
    int m_family;

    explicit proto(int protocol_id, int protocol_family)
        : m_protocol(protocol_id)
        , m_family(protocol_family)
    {
    }

public:

    typedef boost::asio::ip::basic_endpoint<proto> endpoint;
    typedef boost::asio::basic_raw_socket<proto> socket;
    typedef boost::asio::ip::basic_resolver<proto> resolver;

    explicit proto()
        : m_protocol(id)
        , m_family(PF_INET)
    {
    }

    static proto v4()
    {
        return proto(id, PF_INET);
    }

    static proto v6()
    {
        return proto(id, PF_INET6);
    }

    int type() const
    {
        return SOCK_RAW;
    }

    int protocol() const
    {
        return m_protocol;
    }

    int family() const
    {
        return m_family;
    }

    friend bool operator==(const proto& l, const proto& r)
    {
        return l.m_protocol == r.m_protocol && l.m_family == r.m_family;
    }

    friend bool operator!=(const proto& l, const proto& r)
    {
        return l.m_protocol != r.m_protocol || l.m_family != r.m_family;
    }
};

struct ip_packet : public buffer
{
    ip_packet(size_t len) : buffer(len) { }
    ip_packet(const buffer& buf) : buffer(buf) { }

    uint8_t version() const { return (get_byte(0) >> 4) & 0xF; }
    uint16_t header_length() const { return (get_byte(0) & 0xF) * 4; }
    uint8_t type_of_service() const { return get_byte(1); }
    uint16_t total_length() const { return get_word(2); }
    uint16_t identification() const { return get_word(4);  }
    uint16_t fragment_offset() const { return get_word(6) & 0x1FFF; }
    uint8_t time_to_live() const { return get_byte(8); }
    uint8_t protocol() const { return get_byte(9); }
    uint16_t header_checksum() const { return get_word(10); }
    bool dont_fragment() const { return (get_byte(6) & 0x40) != 0; }
    bool more_fragments() const { return (get_byte(6) & 0x20) != 0; }
    boost::asio::ip::address_v4 source_address() const { return boost::asio::ip::address_v4({get_byte(12), get_byte(13), get_byte(14), get_byte(15)}); }
    boost::asio::ip::address_v4 destination_address() const { return boost::asio::ip::address_v4({get_byte(16), get_byte(17), get_byte(18), get_byte(19)}); }
    template<class packet> std::shared_ptr<packet> envelope() const { return std::make_shared<packet>(buffer::push_head()); }
    template<class packet> std::shared_ptr<packet> payload() const { return std::make_shared<packet>(buffer::pop_head(header_length())); }
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
    uint16_t checksum() const { return get_word(2); }
    uint16_t identifier() const { return get_word(4); }
    uint16_t sequence_number() const { return get_word(6); }
    uint8_t pointer() const { return get_byte(4); }
    uint16_t mtu() const { return get_word(6); }
    boost::asio::ip::address_v4 gateway() const { return boost::asio::ip::address_v4({get_byte(4), get_byte(5), get_byte(6), get_byte(7)}); }
    template<class packet> std::shared_ptr<packet> envelope() const { return std::make_shared<packet>(buffer::push_head()); }
    template<class packet> std::shared_ptr<packet> payload() const { return std::make_shared<packet>(buffer::pop_head(8)); }

    static std::shared_ptr<icmp_packet> make_ping_packet(uint16_t id, uint16_t seq, std::shared_ptr<buffer> payload = std::make_shared<buffer>("plexus"));
};

struct udp_packet : public buffer
{
    udp_packet(const buffer& buf) : buffer(buf) { }

    uint16_t source_port() const { return get_word(0); }
    uint16_t dest_port() const { return get_word(2); }
    uint16_t length() const { return get_word(4); }
    uint16_t checksum() const { return get_word(6); }
    template<class packet> std::shared_ptr<packet> envelope() const { return std::make_shared<packet>(buffer::push_head()); }
    template<class packet> std::shared_ptr<packet> payload() const { return std::make_shared<packet>(buffer::pop_head(8)); }

    static std::shared_ptr<udp_packet> make_packet(uint16_t src_port, uint16_t dst_port, std::shared_ptr<buffer> payload = std::make_shared<buffer>("plexus"));
};

struct tcp_packet : public buffer
{
    struct option
    {
        option(const buffer& buf) : m_buffer(buf) {}

        const void* value() const { return length() > 2 ? m_buffer.data() + 2 : 0; }
        uint8_t type() const { return m_buffer.size() ? m_buffer.get_byte(0) : 0; }
        uint8_t length() const { return m_buffer.size() > 1 ? m_buffer.get_byte(1) : m_buffer.size(); }
        option next() const { return option(m_buffer.pop_head(length())); }

    private:

        buffer m_buffer;
    };

    enum flag
    {
        fin = 0x01,
        syn = 0x02,
        rst = 0x04,
        push = 0x08,
        ack = 0x10,
        urg = 0x20
    };

    tcp_packet(const buffer& buf) : buffer(buf) { }

    uint16_t source_port() const { return get_word(0); }
    uint16_t dest_port() const { return get_word(2); }
    uint32_t seq_number() const { return get_dword(4); }
    uint32_t ack_number() const { return get_dword(8); }
    uint8_t data_offset() const { return get_byte(12) >> 4; }
    uint8_t flags() const { return get_byte(13); }
    uint16_t window() const { return get_word(14); }
    uint16_t checksum() const { return get_word(16); }
    uint16_t urgent_pointer() const { return get_word(18); }
    option options() const { return option(buffer::pop_tail(data_offset() * 4).pop_head(20)); }
    template<class packet> std::shared_ptr<packet> envelope() const { return std::make_shared<packet>(buffer::push_head()); }
    template<class packet> std::shared_ptr<packet> payload() const { return std::make_shared<packet>(buffer::pop_head(data_offset() * 4)); }

    static std::shared_ptr<tcp_packet> make_syn_packet(uint16_t src_port, uint16_t dst_port, std::shared_ptr<buffer> payload = std::make_shared<buffer>("plexus"));
};

}}}
