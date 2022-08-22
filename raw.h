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

class buffer
{
    size_t m_size;
    boost::shared_array<uint8_t> m_buffer;

    uint8_t* m_beg;
    uint8_t* m_end;

    buffer(boost::shared_array<uint8_t> buffer, size_t size, uint8_t* beg, uint8_t* end)
        : m_size(size)
        , m_buffer(buffer)
        , m_beg(beg)
        , m_end(end)
    {
    }

public:

    buffer(size_t size, size_t padding = 0)
        : m_size(size + padding)
        , m_buffer(new uint8_t[m_size])
        , m_beg(m_buffer.get() + padding)
        , m_end(m_buffer.get() + m_size)
    {
        std::memset(m_buffer.get(), 0, m_size);
    }

    buffer(const char* data, size_t padding = 0) 
        : m_size(std::strlen(data) + padding)
        , m_buffer(new uint8_t[m_size])
        , m_beg(m_buffer.get() + padding)
        , m_end(m_buffer.get() + m_size)
    {
        std::memset(m_buffer.get(), 0, m_end - m_beg);
        std::memcpy(m_beg, data, std::strlen(data));
    }
    
    buffer(const std::vector<uint8_t>& data, size_t padding = 0) 
        : m_size(data.size() + padding)
        , m_buffer(new uint8_t[m_size])
        , m_beg(m_buffer.get() + padding)
        , m_end(m_buffer.get() + m_size)
    {
        std::memset(m_buffer.get(), 0, m_end - m_beg);
        std::memcpy(m_beg, data.data(), data.size());
    }

    buffer(const buffer& other)
        : m_size(other.m_size)
        , m_buffer(other.m_buffer)
        , m_beg(other.m_beg)
        , m_end(other.m_end)
    {
    }

    virtual ~buffer() { }

    size_t head() const
    {
        return m_beg - m_buffer.get();
    }

    size_t tail() const
    {
        return m_buffer.get() + m_size - m_end;
    }

    uint8_t* begin()
    {
        return m_beg;
    }

    const uint8_t* begin() const
    {
        return m_beg;
    }

    uint8_t* end()
    {
        return m_end;
    }

    const uint8_t* end() const
    {
        return m_end;
    }

    size_t size() const
    {
        return m_end - m_beg;
    }

    void set_byte(size_t pos, uint8_t val)
    {
        uint8_t* ptr = m_beg + pos;
        if (ptr >= m_end)
            throw std::out_of_range("set_byte: out of range");
        *ptr = val;
    }

    uint8_t get_byte(size_t pos) const
    {
        uint8_t* ptr = m_beg + pos;
        if (ptr >= m_end)
            throw std::out_of_range("get_byte: out of range");
        return *ptr;
    }

    void set_word(size_t pos, uint16_t val)
    {
        uint8_t* ptr = m_beg + pos;
        if (ptr + sizeof(uint16_t) > m_end)
            throw std::out_of_range("set_word: out of range");
        *(uint16_t*)(ptr) = htons(val);
    }

    uint16_t get_word(size_t pos) const
    {
        uint8_t* ptr = m_beg + pos;
        if (ptr + sizeof(uint16_t) > m_end)
            throw std::out_of_range("get_word: out of range");
        return ntohs(*(uint16_t*)ptr);
    }

    void set_dword(size_t pos, uint32_t val)
    {
        uint8_t* ptr = m_beg + pos;
        if (ptr + sizeof(uint32_t) > m_end)
            throw std::out_of_range("set_dword: out of range");
        *(uint32_t*)(ptr) = htonl(val);
    }

    uint32_t get_dword(size_t pos) const
    {
        uint8_t* ptr = m_beg + pos;
        if (ptr + sizeof(uint32_t) > m_end)
            throw std::out_of_range("get_dword: out of range");
        return ntohl(*(uint32_t*)ptr);
    }

    buffer pop_head(size_t size) const
    {
        uint8_t* ptr = m_beg - size;
        if (ptr < m_buffer.get())
            throw std::out_of_range("pop_head: out of range");
        return buffer(m_buffer, m_size, ptr, m_end);
    }

    buffer push_head(size_t size) const
    {
        uint8_t* ptr = m_beg + size;
        if (ptr > m_end)
            throw std::runtime_error("push_head: out of range");
        return buffer(m_buffer, m_size, ptr, m_end);
    }

    buffer push_tail(size_t size) const
    {
        uint8_t* ptr = m_end + size;
        if (ptr > m_buffer.get() + m_size)
            throw std::runtime_error("push_tail: out of range");
        return buffer(m_buffer, m_size, m_beg, ptr);
    }

    buffer pop_tail(size_t size) const
    {
        uint8_t* ptr = m_end - size;
        if (ptr < m_beg)
            throw std::runtime_error("pop_tail: out of range");
        return buffer(m_buffer, m_size, m_beg, ptr);
    }

    void move_head(size_t size, bool top)
    {
        uint8_t* ptr = top ? m_beg - size : m_beg + size;
        if (ptr < m_buffer.get() || ptr > m_end)
            throw std::out_of_range("pop_head: out of range");
        m_beg = ptr;
    }

    void move_tail(size_t size, bool top)
    {
        uint8_t* ptr = top ? m_end - size : m_end + size;
        if (ptr < m_beg || ptr > m_buffer.get() + m_size)
            throw std::runtime_error("pop_tail: out of range");
        m_end = ptr;
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

    uint8_t version() const { return (get_byte(0) >> 4) & 0xf; }
    uint16_t header_length() const { return (get_byte(0) & 0xf) * 4; }
    uint8_t type_of_service() const { return get_byte(1); }
    uint16_t total_length() const { return get_word(2); }
    uint16_t identification() const { return get_word(4);  }
    uint16_t fragment_offset() const { return get_word(6) & 0x1fff; }
    uint8_t time_to_live() const { return get_byte(8); }
    uint8_t protocol() const { return get_byte(9); }
    uint16_t header_checksum() const { return get_word(10); }
    bool dont_fragment() const { return (get_byte(6) & 0x40) != 0; }
    bool more_fragments() const { return (get_byte(6) & 0x20) != 0; }
    boost::asio::ip::address_v4 source_address() const { return boost::asio::ip::address_v4({get_byte(12), get_byte(13), get_byte(14), get_byte(15)}); }
    boost::asio::ip::address_v4 destination_address() const { return boost::asio::ip::address_v4({get_byte(16), get_byte(17), get_byte(18), get_byte(19)}); }
    template<class packet> std::shared_ptr<packet> payload() const { return std::make_shared<packet>(buffer::push_head(header_length())); }
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
    template<class packet> std::shared_ptr<packet> payload() const { return std::make_shared<packet>(buffer::push_head(8)); }

    static std::shared_ptr<icmp_packet> make_ping_packet(uint16_t id, uint16_t seq, std::shared_ptr<buffer> data = std::make_shared<buffer>(8, 8));
};

struct udp_packet : public buffer
{
    udp_packet(const buffer& buf) : buffer(buf) { }

    uint16_t source_port() const { return get_word(0); }
    uint16_t dest_port() const { return get_word(2); }
    uint16_t length() const { return get_word(4); }
    uint16_t checksum() const { return get_word(6); }
    template<class packet> std::shared_ptr<packet> payload() const { return std::make_shared<packet>(buffer::push_head(8)); }

    static std::shared_ptr<udp_packet> make_packet(uint16_t sport, uint16_t dport, std::shared_ptr<buffer> data = std::make_shared<buffer>("plexus", 8));
};

struct tcp_packet : public buffer
{
    struct option
    {
        option(const buffer& buf) : m_buffer(buf) {}

        const void* value() const { return length() > 2 ? m_buffer.begin() + 2 : 0; }
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
    option options() const { return option(buffer::push_head(20).pop_tail(buffer::size() - data_offset() * 4)); }
    template<class packet> std::shared_ptr<packet> payload() const { return std::make_shared<packet>(buffer::push_head(data_offset() * 4)); }

    static std::shared_ptr<tcp_packet> make_syn_packet(uint16_t sport, uint16_t dport, uint32_t seq, std::shared_ptr<buffer> data = std::make_shared<buffer>("plexus", 60));
};

}}}
