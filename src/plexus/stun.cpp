/*
 * Copyright (c) 2022 Novemus Band. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 */

#include <plexus/network.h>
#include <plexus/features.h>
#include <plexus/utils.h>
#include <tubus/buffer.h>
#include <wormhole/logger.h>
#include <boost/asio/error.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>

#ifndef _WIN32
#include <netinet/in.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#else
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
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

typedef std::array<uint8_t, 16> transaction_id;

namespace msg
{
    const size_t header_size = 20;
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
                    throw plexus::context_error(__FUNCTION__, "wrong attribute data");

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
                    throw plexus::context_error(__FUNCTION__, "wrong endpoint data");

                return plexus::endpoint {
                    boost::asio::ip::make_address(utils::format("%d.%d.%d.%d", ptr[8], ptr[9], ptr[10], ptr[11])),
                    read_short(ptr, 6)
                };
            }
            else if (ptr[5] == flag::ip_v6)
            {
                if (length != 20u)
                    throw plexus::context_error(__FUNCTION__, "wrong endpoint data");

                plexus::endpoint {
                    boost::asio::ip::make_address(utils::format("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", ptr[8], ptr[9], ptr[10], ptr[11], ptr[12], ptr[13], ptr[14], ptr[15], ptr[16], ptr[17], ptr[18], ptr[19], ptr[20], ptr[21], ptr[22], ptr[23])),
                    read_short(ptr, 6)
                };
            }
        }

        if (type() == msg::binding_response)
            throw plexus::context_error(__FUNCTION__, utils::format("attribute %d not found", kind));

        return plexus::endpoint {};
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

    uint16_t length() const
    {
        return read_short((uint8_t*)data(), 2);
    }

    std::string error() const
    {
        if (type() == msg::binding_error_response)
        {
            const uint8_t* ptr = fetch_attribute_place(attr::error_code);
            if (ptr)
            {
                uint16_t length = read_short(ptr, 2);
                return std::string((const char*)ptr + 8, length - 4);
            }
            throw plexus::context_error(__FUNCTION__, "error code attribute not found");
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

class client_impl : public stun_client
{
    boost::asio::io_context& m_io;
    plexus::endpoint m_stun;
    plexus::endpoint m_udp;
    plexus::endpoint m_tcp;

public:

    client_impl(boost::asio::io_context& io, const plexus::endpoint& stun, const plexus::endpoint& udp, const plexus::endpoint& tcp) 
        : m_io(io)
        , m_udp(udp)
        , m_tcp(tcp)
        , m_stun(stun)
    {
        if (m_udp.port == 0)
        {
            boost::asio::ip::udp::socket socket(io, stun.address.is_v6() ? boost::asio::ip::udp::v6() : boost::asio::ip::udp::v4());
            socket.set_option(boost::asio::socket_base::reuse_address(true));
            socket.bind(udp);

            auto ep = socket.local_endpoint();
            m_udp.address = ep.address();
            m_udp.port = ep.port();
        }

        if (m_tcp.port == 0)
        {
            boost::asio::ip::tcp::socket socket(io, stun.address.is_v6() ? boost::asio::ip::tcp::v6() : boost::asio::ip::tcp::v4());
            socket.set_option(boost::asio::socket_base::reuse_address(true));
            socket.bind(tcp);

            auto ep = socket.local_endpoint();
            m_tcp.address = ep.address();
            m_tcp.port = ep.port();
        }
    }

    message exec_udp_binding(boost::asio::yield_context yield, std::shared_ptr<plexus::network::udp_socket> sock, const plexus::endpoint& to, const plexus::endpoint& from, const message& req = message(0), int64_t deadline = 4600)
    {
        auto timer = [start = boost::posix_time::microsec_clock::universal_time()]()
        {
            return boost::posix_time::microsec_clock::universal_time() - start;
        };

        message res;

        int64_t timeout = 200;
        while (timer().total_milliseconds() < deadline)
        {
            sock->send_to(req, to, yield, timeout);

            try
            {
                res.truncate(sock->receive_from(res, from, yield, timeout));

                if (timer().total_milliseconds() >= deadline)
                    throw plexus::timeout_error(__FUNCTION__);
                else if (req.transaction() != res.transaction())
                    continue;

                switch (res.type())
                {
                    case msg::binding_response:
                    {
                        auto me = res.mapped_endpoint();
                        auto se = res.source_endpoint();
                        auto ce = res.changed_endpoint();

                        _trc_ << "mapped_endpoint=" << me
                              << " source_endpoint=" << se
                              << " changed_endpoint=" << ce;
                        break;
                    }
                    case msg::binding_request:
                        break;
                    case msg::binding_error_response:
                        throw plexus::context_error(__FUNCTION__, res.error());
                    default:
                        throw plexus::context_error(__FUNCTION__, "server responded with unexpected message type");
                }

                return res;
            }
            catch(const boost::system::system_error& ex)
            {
                if (ex.code() != boost::asio::error::operation_aborted)
                    throw plexus::context_error(__FUNCTION__, ex.code());

                _trc_ << ex.what();

                timeout = std::min<int64_t>(1600, timeout * 2);
            }
        } 

        throw plexus::timeout_error(__FUNCTION__);
    }

    message exec_tcp_binding(boost::asio::yield_context yield, const plexus::endpoint& bind, const plexus::endpoint& stun, const message& req = message(0), int64_t deadline = 10000)
    {
        auto timeout = [deadline, start = boost::posix_time::microsec_clock::universal_time()]()
        {
            return std::max<int64_t>(deadline - (boost::posix_time::microsec_clock::universal_time() - start).total_milliseconds(), 0);
        };

        try
        {
            auto sock = plexus::network::create_tcp_socket(m_io, bind, stun);
            sock->connect(yield, timeout());

            if (sock->write(req, yield, timeout()) != req.size())
                throw plexus::context_error(__FUNCTION__, "can't write message");

            message res;
            if (sock->read(boost::asio::buffer(res.data(), msg::header_size), yield, timeout()) != msg::header_size)
                throw plexus::context_error(__FUNCTION__, "can't read message header");

            if (res.length() + msg::header_size > res.size())
                throw plexus::context_error(__FUNCTION__, "too big message size");

            if (sock->read(boost::asio::buffer((uint8_t*)res.data() + msg::header_size, res.length()), yield, timeout()) != res.length())
                throw plexus::context_error(__FUNCTION__, "can't read frame data");

            res.truncate(msg::header_size + res.length());

            if (req.transaction() != res.transaction())
                throw plexus::context_error(__FUNCTION__, "wrong transaction id");

            sock->shutdown();

            switch (res.type())
            {
                case msg::binding_response:
                {
                    _trc_ << "mapped_endpoint=" << res.mapped_endpoint()
                          << " source_endpoint=" << res.source_endpoint()
                          << " changed_endpoint=" << res.changed_endpoint();
                    break;
                }
                case msg::binding_request:
                    break;
                case msg::binding_error_response:
                    throw plexus::context_error(__FUNCTION__, res.error());
                default:
                    throw plexus::context_error(__FUNCTION__, "server responded with unexpected message type");
            }

            return res;
        }
        catch(const boost::system::system_error& ex)
        {
            throw plexus::context_error(__FUNCTION__, ex.code());
        }
    }

    static bool identical(const plexus::endpoint& lhs, const plexus::endpoint& rhs)
    {
        if(lhs.port != rhs.port)
            return false;

        if (lhs.address != boost::asio::ip::address() && rhs.address != boost::asio::ip::address())
            return lhs == rhs;

        if (lhs.address == boost::asio::ip::address() && rhs.address == boost::asio::ip::address())
            return true;

        auto addr = lhs.address != boost::asio::ip::address() ? lhs.address : rhs.address;
        bool local = false;

#ifndef _WIN32
        struct ifaddrs *ifaddr, *ifa;
        int family, s;
        char host[NI_MAXHOST];

        if (getifaddrs(&ifaddr) == -1)
        {
            _err_ << "getifaddrs() failed: " << errno;
            return false;
        }

        for (ifa = ifaddr; ifa != NULL && !local; ifa = ifa->ifa_next)
        {
            if (ifa->ifa_addr == NULL)
                continue;

            family = ifa->ifa_addr->sa_family;

            if (family == AF_INET || family == AF_INET6)
            {
                s = getnameinfo(ifa->ifa_addr,
                                (family == AF_INET) ? sizeof(struct sockaddr_in) :
                                sizeof(struct sockaddr_in6),
                                host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
                if (s != 0)
                {
                    _err_ << "getnameinfo() failed: " << gai_strerror(s);
                    continue;
                }

                local = addr == boost::asio::ip::make_address(host);
            }
        }

        freeifaddrs(ifaddr);
#else
        ULONG bufferSize = 15000;
        std::vector<BYTE> buffer(bufferSize);
        PIP_ADAPTER_ADDRESSES pAdapterAddresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());

        DWORD dwRetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAdapterAddresses, &bufferSize);

        if (dwRetVal == ERROR_BUFFER_OVERFLOW)
        {
            buffer.resize(bufferSize);
            pAdapterAddresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
            dwRetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAdapterAddresses, &bufferSize);
        }

        if (dwRetVal == NO_ERROR)
        {
            for (PIP_ADAPTER_ADDRESSES pAdapter = pAdapterAddresses; pAdapter != nullptr && !local; pAdapter = pAdapter->Next)
            {
                for (PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pAdapter->FirstUnicastAddress; pUnicast != nullptr && !local; pUnicast = pUnicast->Next)
                {
                    char ipString[INET6_ADDRSTRLEN];
                    if (pUnicast->Address.lpSockaddr->sa_family == AF_INET)
                    {
                        sockaddr_in* pSockAddrV4 = reinterpret_cast<sockaddr_in*>(pUnicast->Address.lpSockaddr);
                        inet_ntop(AF_INET, &(pSockAddrV4->sin_addr), ipString, sizeof(ipString));
                    }
                    else if (pUnicast->Address.lpSockaddr->sa_family == AF_INET6)
                    {
                        sockaddr_in6* pSockAddrV6 = reinterpret_cast<sockaddr_in6*>(pUnicast->Address.lpSockaddr);
                        inet_ntop(AF_INET6, &(pSockAddrV6->sin6_addr), ipString, sizeof(ipString));
                    }

                    local = addr == boost::asio::ip::make_address(ipString);
                }
            }
        }
        else
        {
            _err_ << "GetAdaptersAddresses() failed: " << dwRetVal << std::endl;
        }
#endif
        return local;
    }

    void make_udp_traverse(boost::asio::yield_context yield, traverse& info) noexcept(false)
    {
        _trc_ << "making traverse for udp...";

        auto mapper = plexus::network::create_udp_socket(m_io, m_udp);
        auto binding = exec_udp_binding(yield, mapper, m_stun, m_stun);

        info.udp.force = plexus::firewall { false, true, false, false, firewall::independent, firewall::independent };
        info.udp.hosting = m_udp;
        info.udp.mapping = binding.mapped_endpoint();

        if (!identical(info.udp.hosting, info.udp.mapping))
        {
            info.udp.force.nat = true;

            if (info.udp.hosting.port != info.udp.mapping.port)
            {
                info.udp.force.random_port = true;
            }

            auto changed_full = binding.changed_endpoint();
            auto changed_addr = plexus::endpoint{ changed_full.address, m_stun.port };
            auto changed_port = plexus::endpoint{ m_stun.address, changed_full.port };

            _trc_ << "first mapping test...";

            auto first_endpoint = exec_udp_binding(yield, mapper, changed_full, changed_full).mapped_endpoint();
            if (first_endpoint == info.udp.mapping)
            {
                info.udp.force.mapping = firewall::independent;
            }
            else
            {
                _trc_ << "second mapping test...";

                auto second_endpoint = exec_udp_binding(yield, mapper, changed_addr, changed_addr).mapped_endpoint();
                if (second_endpoint == info.udp.mapping)
                {
                    info.udp.force.mapping = firewall::port_dependent;
                }
                else if (second_endpoint == first_endpoint)
                {
                    info.udp.force.mapping = firewall::address_dependent;
                }
                else
                {
                    info.udp.force.mapping = firewall::address_and_port_dependent;
                }

                if (second_endpoint.address != info.udp.mapping.address || second_endpoint.address != first_endpoint.address)
                {
                    info.udp.force.variable_address = true;
                }
            }

            auto filter = plexus::network::create_udp_socket(m_io);
            try
            {
                _trc_ << "first filtering test...";

                exec_udp_binding(yield, filter, m_stun, changed_full, message(flag::change_address | flag::change_port), 1400);
                info.udp.force.filtering = firewall::independent;
            }
            catch(const plexus::timeout_error&)
            {
                try
                {
                    _trc_ << "second filtering test...";

                    exec_udp_binding(yield, filter, m_stun, changed_addr, message(flag::change_address), 1400);
                    info.udp.force.filtering = firewall::port_dependent;
                }
                catch(const plexus::timeout_error&)
                {
                    try
                    {
                        _trc_ << "third filtering test...";

                        exec_udp_binding(yield, filter, m_stun, changed_port, message(flag::change_port), 1400);
                        info.udp.force.filtering = firewall::address_dependent;
                    }
                    catch(const plexus::timeout_error&)
                    {
                        info.udp.force.filtering = firewall::address_and_port_dependent;
                    }
                }
            }

            info.udp.force.hairpin = false;

            try
            {
                _trc_ << "hairpin test...";

                exec_udp_binding(yield, mapper, info.udp.mapping, info.udp.mapping, message(0), 1400);
                info.udp.force.hairpin = true;
            }
            catch(const plexus::timeout_error&) {}
        }

        _inf_ << "udp traverse: hosting=" << info.udp.hosting << " mapping=" << info.udp.mapping << " firewall=" << info.udp.force;
    }

    void make_tcp_traverse(boost::asio::yield_context yield, traverse& info) noexcept(false)
    {
        _trc_ << "making traverse for tcp...";

        auto binding = exec_tcp_binding(yield, m_tcp, m_stun);

        info.tcp.force = plexus::firewall { false, true, false, false, firewall::independent, firewall::independent };
        info.tcp.hosting = m_tcp;
        info.tcp.mapping = binding.mapped_endpoint();

        if (!identical(info.tcp.hosting, info.tcp.mapping))
        {
            info.tcp.force.nat = true;
            info.tcp.force.filtering = firewall::address_and_port_dependent;

            if (info.tcp.hosting.port != info.tcp.mapping.port)
            {
                info.tcp.force.random_port = true;
            }

            auto changed_full = binding.changed_endpoint();
            auto changed_addr = plexus::endpoint{ changed_full.address, m_stun.port };
            auto changed_port = plexus::endpoint{ m_stun.address, changed_full.port };

            _trc_ << "first mapping test...";

            auto first_endpoint = exec_tcp_binding(yield, m_tcp, changed_full).mapped_endpoint();
            if (first_endpoint == info.tcp.mapping)
            {
                info.tcp.force.mapping = firewall::independent;
            }
            else
            {
                _trc_ << "second mapping test...";

                auto second_endpoint = exec_tcp_binding(yield, m_tcp, changed_addr).mapped_endpoint();
                if (second_endpoint == info.tcp.mapping)
                {
                    info.tcp.force.mapping = firewall::port_dependent;
                }
                else if (second_endpoint == first_endpoint)
                {
                    info.tcp.force.mapping = firewall::address_dependent;
                }
                else
                {
                    info.tcp.force.mapping = firewall::address_and_port_dependent;
                }

                if (second_endpoint.address != info.tcp.mapping.address || second_endpoint.address != first_endpoint.address)
                {
                    info.tcp.force.variable_address = true;
                }
            }

            info.tcp.force.hairpin = false;

            try
            {
                _trc_ << "hairpin test...";

                auto self = plexus::network::create_tcp_socket(m_io, m_tcp, info.tcp.mapping);
                self->connect(yield, 1400);
                self->shutdown();

                info.tcp.force.hairpin = true;
            }
            catch(const std::exception&) { }
        }

        _inf_ << "tcp traverse: hosting=" << info.tcp.hosting << " mapping=" << info.tcp.mapping << " firewall=" << info.tcp.force;
    }

public:

    traverse make_traverse(boost::asio::yield_context yield, protocol proto) noexcept(false) override
    {
        traverse info;

        try
        {
            make_udp_traverse(yield, info);
        }
        catch(const std::exception& ex)
        {
            _wrn_ << "can't make udp traverse: " << ex.what();
        }

        if (proto != protocol::udp)
        {
            try
            {
                make_tcp_traverse(yield, info);
            }
            catch(const std::exception& ex)
            {
                _wrn_ << "can't make tcp traverse: " << ex.what();
            }
        }

        return info;
    }
};

}

std::shared_ptr<plexus::stun_client> create_stun_client(boost::asio::io_context& io, const plexus::endpoint& stun, const plexus::endpoint& udp, const plexus::endpoint& tcp) noexcept(true)
{
    return std::make_shared<plexus::stun::client_impl>(io, stun, udp, tcp);
}

}
