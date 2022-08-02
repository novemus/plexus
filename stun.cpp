/*
 * Copyright (c) 2022 Novemus Band. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 */

#include <iostream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <cstring>
#include <array>
#include <boost/asio/error.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include "network.h"
#include "features.h"
#include "utils.h"
#include "log.h"

#ifndef _WIN32
#include <netinet/in.h>
#else
#include <winsock.h>
#endif

/* Algorithm of polling the STUN server to test firewall

*** parameters ***

SA - source ip address of the stun server
CA - canged ip address of the stun server
SP - source port of the stun server
CP - canged port of the stun server
MA - mapped address
MP - mapped port
AF - state of the address change flag
PF - state of the port change flag

*** testing procedure ***

NAT_TEST: SA, SP, AF=0, PF=0
    Acquire mapped endpoint from source address and source port of the stun server.
    If mapped endpoint is equal to the local endpoint, then there is no NAT go to HAIRPIN_TEST and FILERING_TEST_1 tests,
    otherwise check if the mapping preserves port and go to the MAPPING_TEST_1, HAIRPIN_TEST and FILERING_TEST_1 tests
MAPPING_TEST_1: CA, CP, AF=0, PF=0
    Acquire mapped endpoint from changed address and changed port of the stun server.
    If mapped endpoint is equal to the NAT_TEST endpoint, then there is the independent mapping,
    otherwise check if the address is variable and go to the MAPPING_TEST_2 test
MAPPING_TEST_2: CA, SP, AF=0, PF=0
    Acquire mapped endpoint from changed address and source port of the stun server.
    if mapped endpoint is equal to the "MAPPING_TEST_1" endpoint, then there is the address dependent mapping,
    otherwise there is address and port dependent mapping.
HAIRPIN_TEST: MA, MP, AF=0, PF=0
    Send request to the mapped endpoint.
    If response will be received, then there is a hairpin.
FILERING_TEST_1: SA, SP, AF=1, PF=1
    Tell the stun server to reply from changed address and changed port.
    If response will be received, then there is the endpoint independent filtering,
    otherwise go to the FILERING_TEST_2 test
FILERING_TEST_2: SA, SP, AF=0, PF=1
    Tell the stun server to reply from source address and changed port.
    if response will be received, then there is the address dependent filtering,
    otherwise there is address and port dependent filtering
*/

namespace plexus {

std::ostream& operator<<(std::ostream& stream, const binding& bind)
{
    switch (bind)
    {
        case binding::independent:
            return stream << "independent";
        case binding::address_dependent:
            return stream << "address dependent";
        case binding::address_and_port_dependent:
            return stream << "address and port dependent";
        default:
            return stream << "unknown";
    }
    return stream;
}

namespace stun {

typedef std::array<uint8_t, 16> transaction_id;

namespace msg
{
    const size_t min_size = 20;
    const size_t max_size = 548;
    const uint16_t binding_request = 0x0001;
    const uint16_t binding_response = 0x0101;
    const uint16_t binding_error_response = 0x0111;
}

namespace attr
{
    const uint16_t mapped_address = 0x0001;
    const uint16_t change_request = 0x0003;
    const uint16_t source_address = 0x0004;
    const uint16_t changed_address = 0x0005;
    const uint16_t error_code = 0x0009;
    const uint16_t unknown_attributes = 0x000a;
    const uint16_t reflected_from = 0x000b;
}

namespace flag
{
    const uint8_t ip_v4 = 0x01;
    const uint8_t ip_v6 = 0x02;
    const uint8_t change_address = 0x04;
    const uint8_t change_port = 0x02;
}

inline uint16_t read_short(const uint8_t* array, size_t offset = 0)
{
    return ntohs(*(uint16_t*)(array + offset));
}

inline uint8_t rand_byte()
{
    return utils::random() % 256;
}

inline uint8_t high_byte(uint16_t value)
{
    return uint8_t(value >> 8) & 0xff;
}

inline uint8_t low_byte(uint16_t value)
{
    return uint8_t(value);
}

class message : public network::udp::transfer
{
    const uint8_t* fetch_attribute_place(uint16_t type) const
    {
        static const size_t TYPE_LENGTH_PART_SIZE = 4;

        const uint8_t* ptr = &buffer[20];
        const uint8_t* end = buffer.data() + size();

        while (ptr + TYPE_LENGTH_PART_SIZE < end)
        {
            uint16_t attribute = read_short(ptr, 0);
            uint16_t length = read_short(ptr, 2);

            if (attribute == type)
            {
                if (ptr + length + TYPE_LENGTH_PART_SIZE > end)
                    throw std::runtime_error("wrong attribute data");

                return ptr;
            }

            ptr += length + TYPE_LENGTH_PART_SIZE;
        }

        return 0;
    }

    endpoint fetch_endpoint(uint16_t kind) const
    {
        const uint8_t* ptr = fetch_attribute_place(kind);
        if (ptr)
        {
            uint16_t length = read_short(ptr, 2);
            
            if (ptr[5] == flag::ip_v4)
            {
                if (length != 8u)
                    throw std::runtime_error("wrong endpoint data");

                return endpoint(
                    utils::format("%d.%d.%d.%d", ptr[8], ptr[9], ptr[10], ptr[11]),
                    read_short(ptr, 6)
                );
            }
            else if (ptr[5] == flag::ip_v6)
            {
                if (length != 20u)
                    throw std::runtime_error("wrong endpoint data");

                return endpoint(
                    utils::format("%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d", ptr[8], ptr[9], ptr[10], ptr[11], ptr[12], ptr[13], ptr[14], ptr[15], ptr[16], ptr[17], ptr[18], ptr[19], ptr[20], ptr[21], ptr[22], ptr[23]),
                    read_short(ptr, 6)
                );
            }
        }

        if (type() == msg::binding_response)
            throw std::runtime_error(utils::format("endpoint attribute %d not found", kind));

        return endpoint();
    }

public:

    message(const endpoint& stun, uint8_t flags = 0)
        : transfer(stun)
    {
        buffer = {
            0x00, 0x01, 0x00, 0x08,
            rand_byte(), rand_byte(), rand_byte(), rand_byte(),
            rand_byte(), rand_byte(), rand_byte(), rand_byte(),
            rand_byte(), rand_byte(), rand_byte(), rand_byte(),
            rand_byte(), rand_byte(), rand_byte(), rand_byte(),
            0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, flags
        };
    }

    message(const endpoint& stun, uint16_t type)
        : transfer(stun)
    {
        buffer = {
            high_byte(type), low_byte(type), 0x00, 0x00,
            rand_byte(), rand_byte(), rand_byte(), rand_byte(),
            rand_byte(), rand_byte(), rand_byte(), rand_byte(),
            rand_byte(), rand_byte(), rand_byte(), rand_byte(),
            rand_byte(), rand_byte(), rand_byte(), rand_byte()
        };
    }

    message(size_t size) : transfer(size)
    {
    }
    
    transaction_id transaction() const
    {
        return {
             buffer[4], buffer[5], buffer[6], buffer[7],
             buffer[8], buffer[9], buffer[10], buffer[11],
             buffer[12], buffer[13], buffer[14], buffer[15],
             buffer[16], buffer[17], buffer[18], buffer[19]
         };
    }

    uint16_t type() const
    {
        return read_short(buffer.data());
    }

    uint16_t size() const
    {
        return 20u + read_short(buffer.data(), 2);
    }

    std::string error() const
    {
        if (type() == msg::binding_error_response)
        {
            const uint8_t* ptr = fetch_attribute_place(attr::error_code);
            if (ptr)
            {
                uint16_t length = read_short(ptr, 2);
                return std::string((const char*)ptr + 8, length - 8);
            }
            throw std::runtime_error("error code attribute not found");
        }
        return std::string();
    }

    endpoint source_endpoint() const
    {
        return fetch_endpoint(attr::source_address);
    }

    endpoint changed_endpoint() const
    {
        return fetch_endpoint(attr::changed_address);
    }

    endpoint mapped_endpoint() const
    {
        return fetch_endpoint(attr::mapped_address);
    }
};

typedef std::shared_ptr<message> message_ptr;

struct handshake : public network::udp::transfer
{
    handshake(const endpoint& peer, uint8_t flag) : transfer(peer)
    {
        buffer = {
            rand_byte(), rand_byte(), rand_byte(), flag,
            rand_byte(), rand_byte(), rand_byte(), 0
        };

        for (size_t i = 0; i < 8; ++i)
        {
            if (i < 7)
            {
                buffer[7] ^= buffer[i];
            }
        }
    }

    handshake() : transfer(8) { }

    bool valid(const endpoint& peer) const
    {
        if (peer == remote)
        {
            uint8_t hash = buffer[7];

            for (size_t i = 0; i < 8; ++i)
            {
                if (i < 7)
                {
                    hash ^= buffer[i];
                }
            }

            if (hash != 0)
                throw plexus::handshake_error();

            return true;
        }

        return false;
    }

    uint8_t flag() const
    {
        return buffer[3];
    }
};

bool is_public_ip(const boost::asio::ip::address_v4& ip)
{
    auto a = ip.to_uint();
    return !((a >= 0x0A000000) && (a <= 0x0AFFFFFF)) &&
           !((a >= 0xAC100000) && (a <= 0xAC1FFFFF)) &&
           !((a >= 0xC0A80000) && (a <= 0xC0A8FFFF));
}

class session
{
    endpoint m_local;
    std::shared_ptr<udp> m_udp;
    std::shared_ptr<icmp> m_icmp;

public:

    session(const endpoint& local)
        : m_local(local)
        , m_udp(create_udp_channel(local))
        , m_icmp(create_icmp_channel(local.first))
    {
    }

    message_ptr exec_stun_binding(const endpoint& stun, uint8_t flags = 0, int64_t deadline = 4600)
    {
        auto timer = [start = boost::posix_time::microsec_clock::universal_time()]()
        {
            return boost::posix_time::microsec_clock::universal_time() - start;
        };

        message_ptr request = std::make_shared<message>(stun, flags);
        message_ptr response = std::make_shared<message>(msg::max_size);

        int64_t timeout = 200;
        while (timer().total_milliseconds() < deadline)
        {
            m_udp->send(request, timeout);

            try
            {
                m_udp->receive(response, timeout);

                if (timer().total_milliseconds() >= deadline)
                    throw plexus::timeout_error();
                else if (request->transaction() != response->transaction())
                    continue;

                switch (response->type())
                {
                    case msg::binding_response:
                    {
                        endpoint me = response->mapped_endpoint();
                        endpoint se = response->source_endpoint();
                        endpoint ce = response->changed_endpoint();

                        _dbg_ << "mapped_endpoint=" << me.first << ":" << me.second
                              << " source_endpoint=" << se.first << ":" << se.second
                              << " changed_endpoint=" << ce.first << ":" << ce.second;
                        break;
                    }
                    case msg::binding_request:
                        break;
                    case msg::binding_error_response:
                        throw std::runtime_error("server responded with an error: " + response->error());
                    default:
                        throw std::runtime_error("server responded with unexpected message type");
                }

                return response;
            }
            catch(const boost::system::system_error& ex)
            {
                if (ex.code() != boost::asio::error::operation_aborted)
                    throw;

                _trc_ << ex.what();

                timeout = std::min<int64_t>(1600, timeout * 2);
            }
        } 

        throw plexus::timeout_error();
    }

    void handshake_peer_forward(const endpoint& peer, int64_t deadline) noexcept(false)
    {
        auto timer = [start = boost::posix_time::microsec_clock::universal_time()]()
        {
            return boost::posix_time::microsec_clock::universal_time() - start;
        };

        std::shared_ptr<handshake> out = std::make_shared<handshake>(peer, 0);
        std::shared_ptr<handshake> in = std::make_shared<handshake>();

        int64_t timeout = std::max<int64_t>(2000, std::min<int64_t>(4000, deadline / 8));
        while (timer().total_milliseconds() < deadline)
        {
            try
            {
                m_udp->send(out, timeout);
                
                if (in->valid(peer))
                {
                    if (out->flag() == 0)
                    {
                        _dbg_ << "welcome peer=" << in->remote.first << ":" << in->remote.second;
                        out = std::make_shared<handshake>(peer, 1);
                    }
                    else
                    {
                        _dbg_ << "handshake peer=" << in->remote.first << ":" << in->remote.second;
                        return;
                    }
                }

                m_udp->receive(in, timeout);
            }
            catch(const boost::system::system_error& ex)
            {
                if (ex.code() != boost::asio::error::operation_aborted)
                    throw;

                _trc_ << ex.what();
            }
        }

        throw plexus::timeout_error();
    }

    void handshake_peer_backward(const endpoint& peer, int64_t deadline) noexcept(false)
    {
        auto timer = [start = boost::posix_time::microsec_clock::universal_time()]()
        {
            return boost::posix_time::microsec_clock::universal_time() - start;
        };

        std::shared_ptr<handshake> out = std::make_shared<handshake>(peer, 1);
        std::shared_ptr<handshake> in = std::make_shared<handshake>();

        int64_t timeout = std::max<int64_t>(2000, std::min<int64_t>(4000, deadline / 8));
        while (timer().total_milliseconds() < deadline)
        {
            try
            {
                m_udp->receive(in, timeout);

                if (in->valid(peer))
                {
                    if (in->flag() == 0)
                    {
                        _dbg_ << "welcome peer=" << in->remote.first << ":" << in->remote.second;
                    }
                    else
                    {
                        _dbg_ << "handshake peer=" << in->remote.first << ":" << in->remote.second;
                        return;
                    }

                    m_udp->send(out, timeout);
                }
            }
            catch(const boost::system::system_error& ex)
            {
                if (ex.code() != boost::asio::error::operation_aborted)
                    throw;

                _trc_ << ex.what();
            }
        }

        throw plexus::timeout_error();
    }

    void punch_hole_to_peer(const endpoint& peer, int64_t deadline) noexcept(false)
    {
        auto clock = [start = boost::posix_time::microsec_clock::universal_time()]()
        {
            return boost::posix_time::microsec_clock::universal_time() - start;
        };

        static const uint8_t MAX_TRACE_HORES = plexus::utils::getenv<uint8_t>("PLEXUS_MAX_TRACE_HORES", 7);

        uint8_t hops = 2;
        int64_t timeout = deadline / 30;

        while (clock().total_milliseconds() < deadline)
        {
            std::shared_ptr<udp::transfer> punch = std::make_shared<udp::transfer>(peer, std::vector<uint8_t>{
                rand_byte(), rand_byte(), rand_byte(), rand_byte(),
                rand_byte(), rand_byte(), rand_byte(), rand_byte()
            });

            m_udp->send(punch, timeout, hops);
            m_udp->send(punch, timeout, hops++);

            try
            {
                auto timer = [start = boost::posix_time::microsec_clock::universal_time()]()
                {
                    return boost::posix_time::microsec_clock::universal_time() - start;
                };

                do {
                    auto envelope = std::make_shared<ip_packet>(4096);

                    m_icmp->receive(std::make_shared<icmp::transfer>(envelope), timeout);

                    auto icmp = envelope->payload<icmp_packet>();
                    if (icmp->type() == icmp_packet::time_exceeded)
                    {
                        auto ip = icmp->payload<ip_packet>();
                        if (ip->protocol() == IPPROTO_UDP)
                        {
                            auto udp = ip->payload<udp_packet>();
                            if (udp->source_port() == m_local.second)
                            {
                                if (is_public_ip(envelope->source_address()))
                                    return;
                                else
                                    break;
                            }
                        }
                    }
                }
                while (timer().total_milliseconds() < timeout);
            }
            catch(const boost::system::system_error& ex)
            {
                if (ex.code() != boost::asio::error::operation_aborted)
                    throw;

                if (hops >= MAX_TRACE_HORES)
                    return;
                    
                _trc_ << ex.what();
            }
        }

        throw plexus::timeout_error();
    }
};

class udp_puncher : public puncher
{
    endpoint m_stun;
    endpoint m_local;

public:

    udp_puncher(const endpoint& stun, const endpoint& local)
        : m_stun(stun)
        , m_local(local)
    {
    }

    traverse explore_network() noexcept(false) override
    {
        traverse state = {0};
        auto mapper = std::make_shared<session>(m_local);

        _dbg_ << "nat test...";
        message_ptr response = mapper->exec_stun_binding(m_stun);

        endpoint mapped = response->mapped_endpoint();
        endpoint source = response->source_endpoint();
        endpoint changed = response->changed_endpoint();

        if (mapped != m_local)
        {
            state.nat = 1;
            state.random_port = mapped.second != m_local.second ? 1 : 0;
            
            _dbg_ << "first mapping test...";
            endpoint fst_mapped = mapper->exec_stun_binding(changed)->mapped_endpoint();

            state.variable_address = mapped.first != fst_mapped.first ? 1 : 0;

            if (fst_mapped == mapped)
            {
                state.mapping = binding::independent;
            }
            else
            {
                _dbg_ << "second mapping test...";
                endpoint snd_mapped = mapper->exec_stun_binding(endpoint{changed.first, source.second})->mapped_endpoint();

                state.mapping = snd_mapped == fst_mapped ? binding::address_dependent : binding::address_and_port_dependent;
            }
        }
        else
        {
            state.random_port = 0;
            state.variable_address = 0;
            state.mapping = binding::independent;
        }

        try
        {
            _dbg_ << "hairpin test...";
            mapper->exec_stun_binding(mapped, 0, 1400);
            state.hairpin = 1;
        }
        catch(const plexus::timeout_error&) { }

        auto filterer = std::make_shared<session>(endpoint(m_local.first, m_local.second + 1));
        try
        {
            _dbg_ << "first filtering test...";
            filterer->exec_stun_binding(m_stun, flag::change_address | flag::change_port, 1400);
            state.filtering = binding::independent;
        }
        catch(const plexus::timeout_error&)
        {
            try
            {
                _dbg_ << "second filtering test...";
                filterer->exec_stun_binding(m_stun, flag::change_port, 1400);
                state.filtering = binding::address_dependent;
            }
            catch(const plexus::timeout_error&)
            {
                state.filtering = binding::address_and_port_dependent;
            }
        }

        _inf_ << "\ntraverse:"
              << "\n\tnat: " << (state.nat ? "true" : "false")
              << "\n\tmapping: " <<  (binding)state.mapping
              << "\n\tfiltering: " << (binding)state.filtering
              << "\n\trandom port: " << (state.random_port ? "true" : "false")
              << "\n\tvariable address: " << (state.variable_address ? "true" : "false")
              << "\n\thairpin: " << (state.hairpin ? "true" : "false");

        return state;
    }

    endpoint punch_udp_hole() noexcept(false) override
    {
        _dbg_ << "punching udp hole...";

        auto puncher = std::make_shared<session>(m_local);
        return puncher->exec_stun_binding(m_stun)->mapped_endpoint();
    }

    endpoint punch_udp_hole_to_peer(const endpoint& peer) noexcept(false) override
    {
        _dbg_ << "punching udp hole to peer...";

        auto puncher = std::make_shared<session>(m_local);
        puncher->punch_hole_to_peer(peer, plexus::utils::getenv<int64_t>("PLEXUS_PUNCH_TIMEOUT", 60000));
        return puncher->exec_stun_binding(m_stun)->mapped_endpoint();
    }

    void reach_peer(const endpoint& peer) noexcept(false) override
    {
        _dbg_ << "reaching peer...";

        auto reacher = std::make_shared<session>(m_local);
        reacher->handshake_peer_forward(peer, plexus::utils::getenv<int64_t>("PLEXUS_HANDSHAKE_TIMEOUT", 60000));
    }

    void await_peer(const endpoint& peer) noexcept(false) override
    {
        _dbg_ << "awaiting peer...";

        auto acceptor = std::make_shared<session>(m_local);
        acceptor->handshake_peer_backward(peer, plexus::utils::getenv<int64_t>("PLEXUS_HANDSHAKE_TIMEOUT", 60000));
    }
};

}

std::shared_ptr<puncher> create_stun_puncher(const endpoint& stun, const endpoint& local)
{
    return std::make_shared<stun::udp_puncher>(stun, local);
}

}
