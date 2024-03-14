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
#include "features.h"
#include "utils.h"
#include <tubus/buffer.h>
#include <logger.h>
#include <boost/asio/error.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>

#ifndef _WIN32
#include <netinet/in.h>
#else
#include <winsock.h>
#endif

/* 
 * Procedure of polling the STUN server to test network traverse
 *
 * SA - source ip address of the stun server
 * CA - canged ip address of the stun server
 * SP - source port of the stun server
 * CP - canged port of the stun server
 * MA - mapped address
 * MP - mapped port
 * AF - state of the address change flag
 * PF - state of the port change flag
 *
 * ***** NAT *****
 *
 * NAT_TEST: SA, SP, AF=0, PF=0
 *      Acquire mapped endpoint from source address and source port of the stun server.
 *      If mapped endpoint is equal to the local endpoint, then there is no NAT,
 *      otherwise check if the mapping preserves port and go to the MAPPING_TEST_1
 *
 * ***** MAPPING *****
 *
 * MAPPING_TEST_1: CA, CP, AF=0, PF=0
 *      Acquire mapped endpoint from changed address and changed port of the stun server.
 *      If mapped endpoint is equal to the NAT_TEST endpoint, then there is the independent mapping,
 *      otherwise check if the port is variable and go to the MAPPING_TEST_2 test
 * MAPPING_TEST_2: CA, SP, AF=0, PF=0
 *      Acquire mapped endpoint from changed address and source port of the stun server.
 *      if mapped endpoint is equal to the NAT_TEST endpoint, then there is the port dependent mapping,
 *      else if mapped endpoint is equal to the MAPPING_TEST_1 endpoint, then there is the address dependent mapping,
 *      otherwise there is the address and port dependent mapping. Check if the address is variable.
 *
 * ***** FILERING *****
 *
 * FILERING_TEST_1: SA, SP, AF=1, PF=1
 *      Tell the stun server to reply from changed address and changed port.
 *      If response will be received, then there is the endpoint independent filtering,
 *      otherwise go to the FILERING_TEST_2 test
 * FILERING_TEST_2: SA, SP, AF=1, PF=0
 *      Tell the stun server to reply from changed address and source port.
 *      If response will be received, then there is the port dependent filtering,
 *      otherwise go to the FILERING_TEST_3 test
 * FILERING_TEST_3: SA, SP, AF=0, PF=1
 *      Tell the stun server to reply from source address and changed port.
 *      If response will be received, then there is the address dependent filtering,
 *      otherwise there is the address and port dependent filtering
 * 
 * ***** HAIRPIN *****
 *
 * HAIRPIN_TEST: MA, MP, AF=0, PF=0
 *      Send request to the mapped endpoint.
 *      If response will be received, then there is a hairpin.
 *
 */

namespace plexus { namespace stun {

std::string to_string(const network::traverse::binding& value)
{
    switch (value)
    {
        case network::traverse::port_dependent:
            return "port dependent";
        case network::traverse::address_dependent:
            return "address dependent";
        case network::traverse::address_and_port_dependent:
            return "address and port dependent";
        default:
            return "independent";
    }
    return "";
}

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

class message : public tubus::mutable_buffer
{
    const uint8_t* fetch_attribute_place(uint16_t type) const
    {
        static const size_t TYPE_LENGTH_PART_SIZE = 4;

        const uint8_t* ptr = (uint8_t*)data() + 20;
        const uint8_t* end = (uint8_t*)data() + size();

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

    boost::asio::ip::udp::endpoint fetch_endpoint(uint16_t kind) const
    {
        const uint8_t* ptr = fetch_attribute_place(kind);
        if (ptr)
        {
            uint16_t length = read_short(ptr, 2);
            
            if (ptr[5] == flag::ip_v4)
            {
                if (length != 8u)
                    throw std::runtime_error("wrong endpoint data");

                return boost::asio::ip::udp::endpoint(
                    boost::asio::ip::address::from_string(utils::format("%d.%d.%d.%d", ptr[8], ptr[9], ptr[10], ptr[11])),
                    read_short(ptr, 6)
                );
            }
            else if (ptr[5] == flag::ip_v6)
            {
                if (length != 20u)
                    throw std::runtime_error("wrong endpoint data");

                return boost::asio::ip::udp::endpoint(
                    boost::asio::ip::address::from_string(utils::format("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", ptr[8], ptr[9], ptr[10], ptr[11], ptr[12], ptr[13], ptr[14], ptr[15], ptr[16], ptr[17], ptr[18], ptr[19], ptr[20], ptr[21], ptr[22], ptr[23])),
                    read_short(ptr, 6)
                );
            }
        }

        if (type() == msg::binding_response)
            throw std::runtime_error(utils::format("attribute %d not found", kind));

        return boost::asio::ip::udp::endpoint();
    }

public:

    message() : mutable_buffer(msg::max_size)
    {
    }

    message(uint8_t flags) : mutable_buffer(std::vector<uint8_t>{
            0x00, 0x01, 0x00, 0x08,
            utils::random<uint8_t>(), utils::random<uint8_t>(), utils::random<uint8_t>(), utils::random<uint8_t>(),
            utils::random<uint8_t>(), utils::random<uint8_t>(), utils::random<uint8_t>(), utils::random<uint8_t>(),
            utils::random<uint8_t>(), utils::random<uint8_t>(), utils::random<uint8_t>(), utils::random<uint8_t>(),
            utils::random<uint8_t>(), utils::random<uint8_t>(), utils::random<uint8_t>(), utils::random<uint8_t>(),
            0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, flags
        })
    {
    }

    transaction_id transaction() const
    {
        return {
             get<uint8_t>(4), get<uint8_t>(5), get<uint8_t>(6), get<uint8_t>(7),
             get<uint8_t>(8), get<uint8_t>(9), get<uint8_t>(10), get<uint8_t>(11), 
             get<uint8_t>(12), get<uint8_t>(13), get<uint8_t>(14), get<uint8_t>(15),
             get<uint8_t>(16), get<uint8_t>(17), get<uint8_t>(18), get<uint8_t>(19)
         };
    }

    uint16_t type() const
    {
        return read_short((uint8_t*)data());
    }

    uint16_t size() const
    {
        return 20u + read_short((uint8_t*)data(), 2);
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

    boost::asio::ip::udp::endpoint source_endpoint() const
    {
        return fetch_endpoint(attr::source_address);
    }

    boost::asio::ip::udp::endpoint changed_endpoint() const
    {
        return fetch_endpoint(attr::changed_address);
    }

    boost::asio::ip::udp::endpoint mapped_endpoint() const
    {
        return fetch_endpoint(attr::mapped_address);
    }
};

class client_impl : public stun_client
{
    boost::asio::io_service& m_io;
    boost::asio::ip::udp::endpoint m_stun;
    boost::asio::ip::udp::endpoint m_bind;

public:

    client_impl(boost::asio::io_service& io, const boost::asio::ip::udp::endpoint& stun, const boost::asio::ip::udp::endpoint& bind) 
        : m_io(io)
        , m_stun(stun)
        , m_bind(bind)
    {}

    static message exec_binding(std::shared_ptr<plexus::network::udp_socket> udp, boost::asio::yield_context yield, const boost::asio::ip::udp::endpoint& to, const boost::asio::ip::udp::endpoint& from, const message& recv = message(0), int64_t deadline = 4600)
    {
        auto timer = [start = boost::posix_time::microsec_clock::universal_time()]()
        {
            return boost::posix_time::microsec_clock::universal_time() - start;
        };

        message resp;

        int64_t timeout = 200;
        while (timer().total_milliseconds() < deadline)
        {
            udp->send_to(recv, to, yield, timeout);

            try
            {
                resp.truncate(udp->receive_from(resp, from, yield, timeout));

                if (timer().total_milliseconds() >= deadline)
                    throw plexus::timeout_error();
                else if (recv.transaction() != resp.transaction())
                    continue;

                switch (resp.type())
                {
                    case msg::binding_response:
                    {
                        auto me = resp.mapped_endpoint();
                        auto se = resp.source_endpoint();
                        auto ce = resp.changed_endpoint();

                        _dbg_ << "mapped_endpoint=" << me
                              << " source_endpoint=" << se
                              << " changed_endpoint=" << ce;
                        break;
                    }
                    case msg::binding_request:
                        break;
                    case msg::binding_error_response:
                        throw std::runtime_error("server responded with an error: " + resp.error());
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

public:

    network::traverse punch_hole(boost::asio::yield_context yield) noexcept(false) override
    {
        _dbg_ << "punching udp hole to stun...";
        
        network::traverse hole = { { 0 } };

        auto mapper = plexus::network::create_udp_transport(m_io, m_bind);
        auto response = exec_binding(mapper, yield, m_stun, m_stun);
        
        hole.inner_endpoint = mapper->local_endpoint();
        hole.outer_endpoint = response.mapped_endpoint();
        
        auto changed_stun = response.changed_endpoint();

        if (hole.inner_endpoint != hole.outer_endpoint)
        {
            hole.traits.nat = true;

            if (m_bind.port() != hole.outer_endpoint.port())
            {
                hole.traits.random_port = true;
            }

            _dbg_ << "first mapping test...";

            auto first_endpoint = exec_binding(mapper, yield, changed_stun, changed_stun).mapped_endpoint();
            if (first_endpoint == hole.outer_endpoint)
            {
                hole.traits.mapping = network::traverse::independent;
            }
            else
            {
                _dbg_ << "second mapping test...";

                boost::asio::ip::udp::endpoint stun(changed_stun.address(), m_stun.port());
                auto second_endpoint = exec_binding(mapper, yield, stun, stun).mapped_endpoint();
                
                if (second_endpoint == hole.outer_endpoint)
                {
                    hole.traits.mapping = network::traverse::port_dependent;
                }
                else if (second_endpoint == first_endpoint)
                {
                    hole.traits.mapping = network::traverse::address_dependent;
                }
                else
                {
                    hole.traits.mapping = network::traverse::address_and_port_dependent;
                }

                if (second_endpoint.address() != hole.outer_endpoint.address() || second_endpoint.address() != first_endpoint.address())
                {
                    hole.traits.variable_address = true;
                }
            }
        }
        else
        {
            hole.traits.mapping = network::traverse::independent;
        }

        auto filter = plexus::network::create_udp_transport(m_io);
        try
        {
            _dbg_ << "first filtering test...";

            exec_binding(filter, yield, m_stun, changed_stun, message(flag::change_address | flag::change_port), 1400);
            hole.traits.filtering = network::traverse::independent;
        }
        catch(const plexus::timeout_error&)
        {
            try
            {
                _dbg_ << "second filtering test...";

                exec_binding(filter, yield, m_stun, boost::asio::ip::udp::endpoint(changed_stun.address(), m_stun.port()), message(flag::change_address), 1400);
                hole.traits.filtering = network::traverse::port_dependent;
            }
            catch(const plexus::timeout_error&)
            {
                try
                {
                    _dbg_ << "third filtering test...";

                    exec_binding(filter, yield, m_stun, boost::asio::ip::udp::endpoint(m_stun.address(), changed_stun.port()), message(flag::change_port), 1400);
                    hole.traits.filtering = network::traverse::address_dependent;
                }
                catch(const plexus::timeout_error&)
                {
                    hole.traits.filtering = network::traverse::address_and_port_dependent;
                }
            }
        }
        
        try
        {
            _dbg_ << "hairpin test...";

            exec_binding(mapper, yield, hole.outer_endpoint , hole.outer_endpoint , message(0), 1400);
            hole.traits.hairpin = true;
        }
        catch(const plexus::timeout_error&) { }

        _inf_ << "\ntraverse:"
              << "\n\tnat: " << hole.traits.nat
              << "\n\tmapping: " << to_string(hole.traits.mapping)
              << "\n\tfiltering: " << to_string(hole.traits.filtering)
              << "\n\trandom port: " << hole.traits.random_port 
              << "\n\tvariable address: " << hole.traits.variable_address 
              << "\n\thairpin: " << hole.traits.hairpin
              << "\n\tinner endpoint: " << hole.inner_endpoint
              << "\n\touter endpoint: " << hole.outer_endpoint;

        return hole;
    }
};

}

std::shared_ptr<plexus::stun_client> create_stun_client(boost::asio::io_service& io, const boost::asio::ip::udp::endpoint& server, const boost::asio::ip::udp::endpoint& local) noexcept(true)
{
    return std::make_shared<plexus::stun::client_impl>(io, server, local);
}

}
