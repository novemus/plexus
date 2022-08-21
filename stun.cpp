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

inline uint8_t high_byte(uint16_t value)
{
    return uint8_t(value >> 8) & 0xff;
}

inline uint8_t low_byte(uint16_t value)
{
    return uint8_t(value);
}

class message : public plexus::network::buffer
{
    const uint8_t* fetch_attribute_place(uint16_t type) const
    {
        static const size_t TYPE_LENGTH_PART_SIZE = 4;

        const uint8_t* ptr = data() + 20;
        const uint8_t* end = data() + size();

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

    message() : plexus::network::buffer(msg::max_size)
    {
    }

    message(uint8_t flags) : plexus::network::buffer({
            0x00, 0x01, 0x00, 0x08,
            utils::random<uint8_t>(), utils::random<uint8_t>(), utils::random<uint8_t>(), utils::random<uint8_t>(),
            utils::random<uint8_t>(), utils::random<uint8_t>(), utils::random<uint8_t>(), utils::random<uint8_t>(),
            utils::random<uint8_t>(), utils::random<uint8_t>(), utils::random<uint8_t>(), utils::random<uint8_t>(),
            utils::random<uint8_t>(), utils::random<uint8_t>(), utils::random<uint8_t>(), utils::random<uint8_t>(),
            0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, flags
        })
    {
    }

    message(uint16_t type) : plexus::network::buffer({
            high_byte(type), low_byte(type), 0x00, 0x00,
            utils::random<uint8_t>(), utils::random<uint8_t>(), utils::random<uint8_t>(), utils::random<uint8_t>(),
            utils::random<uint8_t>(), utils::random<uint8_t>(), utils::random<uint8_t>(), utils::random<uint8_t>(),
            utils::random<uint8_t>(), utils::random<uint8_t>(), utils::random<uint8_t>(), utils::random<uint8_t>(),
            utils::random<uint8_t>(), utils::random<uint8_t>(), utils::random<uint8_t>(), utils::random<uint8_t>(),
        })
    {
    }

    transaction_id transaction() const
    {
        return {
             get_byte(4), get_byte(5), get_byte(6), get_byte(7),
             get_byte(8), get_byte(9), get_byte(10), get_byte(11), 
             get_byte(12), get_byte(13), get_byte(14), get_byte(15),
             get_byte(16), get_byte(17), get_byte(18), get_byte(19)
         };
    }

    uint16_t type() const
    {
        return read_short(data());
    }

    uint16_t size() const
    {
        return 20u + read_short(data(), 2);
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

class client
{
    class session
    {
        endpoint m_host;
        std::shared_ptr<plexus::network::transport> m_udp;

    public:

        session(const endpoint& host) 
            : m_host(host)
            , m_udp(plexus::network::raw::create_wrapped_udp_transport(host))
        {}

        std::shared_ptr<message> exec_binding(const endpoint& stun, uint8_t flags = 0, int64_t deadline = 4600)
        {
            auto timer = [start = boost::posix_time::microsec_clock::universal_time()]()
            {
                return boost::posix_time::microsec_clock::universal_time() - start;
            };

            auto recv = std::make_shared<message>(flags);
            auto resp = std::make_shared<message>();

            int64_t timeout = 200;
            while (timer().total_milliseconds() < deadline)
            {
                m_udp->send(stun, recv, timeout);

                try
                {
                    m_udp->receive(stun, resp, timeout);

                    if (timer().total_milliseconds() >= deadline)
                        throw plexus::timeout_error();
                    else if (recv->transaction() != resp->transaction())
                        continue;

                    switch (resp->type())
                    {
                        case msg::binding_response:
                        {
                            endpoint me = resp->mapped_endpoint();
                            endpoint se = resp->source_endpoint();
                            endpoint ce = resp->changed_endpoint();

                            _dbg_ << "mapped_endpoint=" << me.first << ":" << me.second
                                << " source_endpoint=" << se.first << ":" << se.second
                                << " changed_endpoint=" << ce.first << ":" << ce.second;
                            break;
                        }
                        case msg::binding_request:
                            break;
                        case msg::binding_error_response:
                            throw std::runtime_error("server responded with an error: " + resp->error());
                        default:
                            throw std::runtime_error("server responded with unexpected message type");
                    }

                    return resp;
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
    };

public:

    static endpoint obtain_endpoint(const endpoint& host, const endpoint& stun) noexcept(false)
    {
        auto pin = std::make_shared<session>(host);
        return pin->exec_binding(stun)->mapped_endpoint();
    }

    static traverse explore_network(const endpoint& host, const endpoint& stun) noexcept(false)
    {
        traverse state = {0};
        auto pin = std::make_shared<session>(host);

        _dbg_ << "nat test...";
        auto response = pin->exec_binding(stun);

        endpoint mapped = response->mapped_endpoint();
        endpoint source = response->source_endpoint();
        endpoint changed = response->changed_endpoint();

        if (mapped != host)
        {
            state.nat = 1;
            state.random_port = mapped.second != host.second ? 1 : 0;
            
            _dbg_ << "first mapping test...";
            endpoint fst_mapped = pin->exec_binding(changed)->mapped_endpoint();

            state.variable_address = mapped.first != fst_mapped.first ? 1 : 0;

            if (fst_mapped == mapped)
            {
                state.mapping = binding::independent;
            }
            else
            {
                _dbg_ << "second mapping test...";
                endpoint snd_mapped = pin->exec_binding(endpoint{changed.first, source.second})->mapped_endpoint();

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
            pin->exec_binding(mapped, 0, 1400);
            state.hairpin = 1;
        }
        catch(const plexus::timeout_error&) { }

        pin = std::make_shared<session>(endpoint(host.first, host.second + 1));
        try
        {
            _dbg_ << "first filtering test...";
            pin->exec_binding(stun, flag::change_address | flag::change_port, 1400);
            state.filtering = binding::independent;
        }
        catch(const plexus::timeout_error&)
        {
            try
            {
                _dbg_ << "second filtering test...";
                pin->exec_binding(stun, stun::flag::change_port, 1400);
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
};

} // namespace stun

template<int proto> class punch_strategy
{
    class handshake : public plexus::network::buffer
    {
        uint64_t m_mask;

        uint8_t get_mask_byte(size_t pos) const
        {
            return uint8_t(m_mask >> (pos * 8));
        }

    public:

        handshake(uint8_t flag, uint64_t mask) : plexus::network::buffer(8), m_mask(mask)
        {
            uint8_t sum = 0;
            for (size_t i = 0; i < 7; ++i)
            {
                uint8_t byte = utils::random<uint8_t>();

                if (i == 0)
                    byte &= flag ? 0xff : 0xfe;

                sum ^= byte;
                set_byte(i, byte ^ get_mask_byte(i));
            }

            set_byte(7, sum ^ get_mask_byte(7));
        }

        handshake(uint64_t mask) : plexus::network::buffer(8), m_mask(mask)
        {
        }

        uint8_t flag() const
        {
            uint8_t sum = get_byte(7) ^ get_mask_byte(7);

            for (size_t i = 0; i < 8; ++i)
                sum ^= get_byte(i) ^ get_mask_byte(i);

            if (sum != 0)
                throw plexus::handshake_error();

            return get_byte(0) ^ get_mask_byte(0) & 0x1;
        }
    };

    static std::shared_ptr<plexus::network::transport> get_transport(const endpoint& host)
    {
        if (proto == IPPROTO_UDP)
        {
            return plexus::network::raw::create_wrapped_udp_transport(host);
        }
        else if (proto == IPPROTO_TCP)
        {
            return plexus::network::raw::create_wrapped_tcp_transport(host);
        }
        throw std::runtime_error("unsupported proto");
    }

public:

    static void handshake_peer_forward(const endpoint& host, const endpoint& peer, uint64_t mask, int64_t deadline) noexcept(false)
    {
        auto timer = [start = boost::posix_time::microsec_clock::universal_time()]()
        {
            return boost::posix_time::microsec_clock::universal_time() - start;
        };

        auto pin = get_transport(host);
        auto out = std::make_shared<handshake>(0, mask);
        auto in = std::make_shared<handshake>(mask);

        int64_t timeout = std::max<int64_t>(2000, std::min<int64_t>(4000, deadline / 8));
        while (timer().total_milliseconds() < deadline)
        {
            try
            {
                pin->send(peer, out, timeout);
                
                if (out->flag() == 1)
                {
                    _dbg_ << "handshake peer=" << peer.first << ":" << peer.second;
                    return;
                }

                pin->receive(peer, in, timeout);

                if (in->flag() == 1)
                {
                    out = std::make_shared<handshake>(1, mask);
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

    static void handshake_peer_backward(const endpoint& host, const endpoint& peer, uint64_t mask, int64_t deadline) noexcept(false)
    {
        auto timer = [start = boost::posix_time::microsec_clock::universal_time()]()
        {
            return boost::posix_time::microsec_clock::universal_time() - start;
        };

        auto pin = get_transport(host);
        auto out = std::make_shared<handshake>(1, mask);
        auto in = std::make_shared<handshake>(mask);

        int64_t timeout = std::max<int64_t>(2000, std::min<int64_t>(4000, deadline / 8));
        while (timer().total_milliseconds() < deadline)
        {
            try
            {
                pin->receive(peer, in, timeout);

                if (in->flag() == 0)
                {
                    pin->send(peer, out, timeout);
                }
                else
                {
                    _dbg_ << "handshake peer=" << peer.first << ":" << peer.second;
                    return;
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

    static endpoint punch_hole_to_peer(const endpoint& host, const endpoint& peer, uint8_t hops) noexcept(false)
    {
        endpoint ep = plexus::stun::client::obtain_endpoint(host, peer);

        auto pin = get_transport(host);
        pin->send(peer, std::make_shared<handshake>(0, 0), 1600, hops);

        return ep;
    }
};

template<int proto> class nat_puncher : public puncher
{
    typedef plexus::punch_strategy<proto> strategy;

    endpoint m_stun;
    endpoint m_local;

public:

    nat_puncher(const endpoint& stun, const endpoint& local)
        : m_stun(stun)
        , m_local(local)
    {
    }

    traverse explore_network() noexcept(false) override
    {
        _dbg_ << "testing network...";
        return plexus::stun::client::explore_network(m_local, m_stun);
    }

    endpoint obtain_endpoint() noexcept(false) override
    {
        _dbg_ << "obtaining endpoint...";
        return plexus::stun::client::obtain_endpoint(m_local, m_stun);
    }

    endpoint punch_hole_to_peer(const endpoint& peer, uint8_t hops) noexcept(false) override
    {
        _dbg_ << "punching hole to peer...";
        return strategy::punch_hole_to_peer(m_local, peer, hops);
    }

    void reach_peer(const endpoint& peer, uint64_t mask) noexcept(false) override
    {
        _dbg_ << "reaching peer...";
        strategy::handshake_peer_forward(m_local, peer, mask, plexus::utils::getenv<int64_t>("PLEXUS_HANDSHAKE_TIMEOUT", 60000));
    }

    void await_peer(const endpoint& peer, uint64_t mask) noexcept(false) override
    {
        _dbg_ << "awaiting peer...";
        strategy::handshake_peer_backward(m_local, peer, mask, plexus::utils::getenv<int64_t>("PLEXUS_HANDSHAKE_TIMEOUT", 60000));
    }
};

std::shared_ptr<puncher> create_udp_puncher(const endpoint& stun, const endpoint& local)
{
    return std::make_shared<nat_puncher<IPPROTO_UDP>>(stun, local);
}

std::shared_ptr<puncher> create_tcp_puncher(const endpoint& stun, const endpoint& local)
{
    return std::make_shared<nat_puncher<IPPROTO_TCP>>(stun, local);
}

}
