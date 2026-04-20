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

std::chrono::minutes cache_period()
{
    static const std::chrono::minutes s_period(utils::getenv<int64_t>("PLEXUS_STUN_CACHE_PERIOD", 30));
    return s_period;
}

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
    const uint16_t xor_mapped_address = 0x0020;
    const uint16_t other_address = 0x802c;
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

inline uint32_t read_long(const uint8_t* array, size_t offset = 0)
{
    return ntohl(*(uint32_t*)(array + offset));
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

                if (kind == attr::xor_mapped_address)
                {
                    uint32_t raw;
                    std::memcpy(&raw, ptr + 8, 4);

                    raw ^= htonl(0x2112A442);

                    return endpoint {
                        boost::asio::ip::address_v4(ntohl(raw)),
                        static_cast<uint16_t>(read_short(ptr, 6) ^ 0x2112)
                    };
                }

                return endpoint {
                    boost::asio::ip::address_v4(read_long(ptr, 8)),
                    read_short(ptr, 6)
                };
            }
            else if (ptr[5] == flag::ip_v6)
            {
                if (length != 20u)
                    throw plexus::context_error(__FUNCTION__, "wrong endpoint data");

                if (kind == attr::xor_mapped_address)
                {
                    uint32_t magic = htonl(0x2112A442);
                    uint8_t mask[16];

                    std::memcpy(mask, &magic, 4);
                    std::memcpy(mask + 4, (uint8_t*)data() + 8, 12);

                    std::array<unsigned char, 16> bytes;
                    std::memcpy(bytes.data(), ptr + 8, 16);

                    for (int i = 0; i < 16; ++i)
                        bytes[i] ^= mask[i];

                    return endpoint {
                        boost::asio::ip::address_v6(bytes),
                        static_cast<uint16_t>(read_short(ptr, 6) ^ 0x2112)
                    };
                }

                std::array<unsigned char, 16> bytes;
                std::memcpy(bytes.data(), ptr + 8, 16);

                return endpoint { boost::asio::ip::address_v6(bytes), read_short(ptr, 6) };
            }
        }

        ptr = fetch_attribute_place(attr::mapped_address);
        return endpoint { ptr && ptr[5] == flag::ip_v6 ? boost::asio::ip::address(boost::asio::ip::address_v6()) : boost::asio::ip::address(boost::asio::ip::address_v4()), 0 };
    }

public:

    message() : mutable_buffer(msg::max_size)
    {
    }

    message(uint8_t flags) : mutable_buffer(std::vector<uint8_t>{
            0x00, 0x01, 0x00, 0x08,
            0x21, 0x12, 0xa4, 0x42,
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
            throw plexus::context_error(__FUNCTION__, "no error code attribute");
        }
        return std::string();
    }

    endpoint source_endpoint() const
    {
        return fetch_endpoint(attr::source_address);
    }

    endpoint changed_endpoint() const
    {
        endpoint ep = fetch_endpoint(attr::other_address);
        return ep.address.is_unspecified() ? fetch_endpoint(attr::changed_address) : ep;
    }

    endpoint mapped_endpoint() const
    {
        endpoint ep = fetch_endpoint(attr::xor_mapped_address);
        return ep.address.is_unspecified() ? fetch_endpoint(attr::mapped_address) : ep;
    }
};

class client_impl : public stun_client
{
    boost::asio::io_context& m_io;
    location m_stun;
    location m_bind;

    struct cache
    {
        static bool get(protocol proto, const endpoint& stun, traverse::hole& hole)
        {
            std::unique_lock<std::mutex> lock(mutex());
            const cache& val = value(proto, stun);

            auto now = std::chrono::steady_clock::now();
            auto age = std::chrono::duration_cast<std::chrono::minutes>(now - val.time);

            if (age < cache_period() && hole.inner.address == val.hole.inner.address && hole.outer.address == val.hole.outer.address)
            {
                hole.force = val.hole.force;
                return true;
            }
            return false;
        }

        static bool set(protocol proto, const endpoint& stun, const traverse::hole& hole)
        {
            std::unique_lock<std::mutex> lock(mutex());
            cache& val = value(proto, stun);

            auto now = std::chrono::steady_clock::now();
            auto age = std::chrono::duration_cast<std::chrono::minutes>(now - val.time);

            if (age > cache_period() || hole.inner.address != val.hole.inner.address || hole.outer.address != val.hole.outer.address || firewall::to_number(hole.force) != firewall::to_number(val.hole.force))
            {
                val.hole = hole;
                val.time = now;
                return true;
            }
            return false;
        }

        cache() : time(std::chrono::steady_clock::now() - std::chrono::hours(24))
        {
        }

    private:

        static std::mutex& mutex()
        {
            static std::mutex s_mutex;
            return s_mutex;
        }

        static cache& value(protocol proto, const endpoint& stun)
        {
            static std::unordered_map<boost::asio::ip::udp::endpoint, cache> s_udp;
            static std::unordered_map<boost::asio::ip::tcp::endpoint, cache> s_tcp;
            return proto == protocol::udp ? s_udp[stun] : s_tcp[stun];
        }

        traverse::hole hole;
        std::chrono::time_point<std::chrono::steady_clock> time;
    };

public:

    client_impl(boost::asio::io_context& io, const location& stun, const location& bind) 
        : m_io(io)
    {
        m_stun.udp = stun.udp;
        m_stun.tcp = stun.tcp;
        m_bind.udp = utils::locate<boost::asio::ip::udp>(bind.udp);
        m_bind.tcp = utils::locate<boost::asio::ip::tcp>(bind.tcp);
    }

    message exec_udp_binding(boost::asio::yield_context yield, std::shared_ptr<network::udp_socket> sock, const endpoint& to, const endpoint& from, uint8_t flag = 0, int64_t deadline = 4600)
    {
        if (to.address.is_unspecified() || from.address.is_unspecified())
            throw plexus::context_error(__FUNCTION__, "bad destination");

        auto timer = [start = boost::posix_time::microsec_clock::universal_time()]()
        {
            return boost::posix_time::microsec_clock::universal_time() - start;
        };

        int64_t timeout = 200;
        while (timer().total_milliseconds() < deadline)
        {
            message req(flag);
            sock->send_to(req, to, yield, timeout);

            try
            {
                message res;
                res.truncate(sock->receive_from(res, from, yield, timeout));

                if (timer().total_milliseconds() >= deadline)
                    throw plexus::timeout_error(__FUNCTION__);
                else if (req.transaction() != res.transaction())
                    continue;

                switch (res.type())
                {
                    case msg::binding_request:
                        break;
                    case msg::binding_response:
                    {
                        _trc_ << "mapped_endpoint=" << res.mapped_endpoint()
                              << " source_endpoint=" << res.source_endpoint()
                              << " changed_endpoint=" << res.changed_endpoint();
                        break;
                    }
                    case msg::binding_error_response:
                    {
                        _err_ << res.error();
                        throw plexus::context_error(__FUNCTION__, res.error());
                    }
                    default:
                    {
                        _err_ << "unexpected stun message " << res.type();
                        throw plexus::context_error(__FUNCTION__, "unexpected stun message");
                    }
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

    message exec_tcp_binding(boost::asio::yield_context yield, const endpoint& bind, const endpoint& stun, uint8_t flag = 0, int64_t deadline = 10000)
    {
        if (stun.address.is_unspecified())
            throw plexus::context_error(__FUNCTION__, "bad destination");

        auto timeout = [deadline, start = boost::posix_time::microsec_clock::universal_time()]()
        {
            return std::max<int64_t>(deadline - (boost::posix_time::microsec_clock::universal_time() - start).total_milliseconds(), 0);
        };

        try
        {
            auto sock = plexus::network::create_tcp_socket(m_io, bind, stun);
            sock->connect(yield, timeout());

            message req(flag);
            if (sock->write(req, yield, timeout()) != req.size())
                throw plexus::context_error(__FUNCTION__, "can't write message");

            message res;
            if (sock->read(boost::asio::buffer(res.data(), msg::header_size), yield, timeout()) != msg::header_size)
                throw plexus::context_error(__FUNCTION__, "can't read message header");

            if (res.length() + msg::header_size > res.size())
                throw plexus::context_error(__FUNCTION__, "too big message size");

            if (sock->read(boost::asio::buffer((uint8_t*)res.data() + msg::header_size, res.length()), yield, timeout()) != res.length())
                throw plexus::context_error(__FUNCTION__, "can't read frame data");

            sock->shutdown();
            res.truncate(msg::header_size + res.length());

            if (req.transaction() != res.transaction())
                throw plexus::context_error(__FUNCTION__, "wrong transaction id");

            switch (res.type())
            {
                case msg::binding_request:
                    break;
                case msg::binding_response:
                {
                    _trc_ << "mapped_endpoint=" << res.mapped_endpoint()
                          << " source_endpoint=" << res.source_endpoint()
                          << " changed_endpoint=" << res.changed_endpoint();
                    break;
                }
                case msg::binding_error_response:
                {
                    _err_ << res.error();
                    throw plexus::context_error(__FUNCTION__, res.error());
                }
                default:
                {
                    _err_ << "unexpected stun message " << res.type();
                    throw plexus::context_error(__FUNCTION__, "unexpected stun message");
                }
            }

            return res;
        }
        catch(const boost::system::system_error& ex)
        {
            throw plexus::context_error(__FUNCTION__, ex.code());
        }
    }

    static endpoint detect_outgoing_endpoint(const endpoint& bind)
    {
        if (!bind.address.is_unspecified() && bind.port != 0)
            return bind;

        boost::asio::io_context io;
        boost::asio::ip::udp::socket socket(io, bind.address.is_v4() ? boost::asio::ip::udp::v4() : boost::asio::ip::udp::v6());
        socket.set_option(boost::asio::socket_base::reuse_address(true));
        socket.bind(bind);

        auto remote = boost::asio::ip::udp::endpoint(
            bind.address.is_v4() ? boost::asio::ip::make_address("8.8.8.8") : boost::asio::ip::make_address("2001:4860:4860::8888"),
            53);

        socket.connect(remote);
        auto local = socket.local_endpoint();

        return endpoint { local.address(), local.port() };
    }

    static bool colocated(const endpoint& lhs, const endpoint& rhs)
    {
        if (lhs.address.is_v4() != rhs.address.is_v4())
            throw plexus::context_error(__FUNCTION__, "not comparable addresses");

        if(lhs.port != rhs.port)
            return false;

        if (!lhs.address.is_unspecified() && !rhs.address.is_unspecified())
            return lhs == rhs;

        if (lhs.address.is_unspecified() && rhs.address.is_unspecified())
            return true;

        auto addr = lhs.address.is_unspecified() ? rhs.address : lhs.address;

        if (addr.is_loopback())
            return true;

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

            if (ifa->ifa_addr->sa_family == AF_INET && addr.is_v4())
            {
                auto* sin = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr);
                local = addr.to_v4() == boost::asio::ip::address_v4(ntohl(sin->sin_addr.s_addr));
            } 
            else if (ifa->ifa_addr->sa_family == AF_INET6 && addr.is_v6())
            {
                auto* sin = reinterpret_cast<struct sockaddr_in6*>(ifa->ifa_addr);
                boost::asio::ip::address_v6::bytes_type bytes;
                std::memcpy(bytes.data(), sin->sin6_addr.s6_addr, 16);
                local = addr.to_v6() == boost::asio::ip::address_v6(bytes, sin->sin6_scope_id);
            }
        }

        freeifaddrs(ifaddr);
#else
        ULONG bufferSize = 15000;
        std::vector<BYTE> buffer(bufferSize);
        PIP_ADAPTER_ADDRESSES pAdapterAddresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());

        ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
        DWORD dwRetVal = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, pAdapterAddresses, &bufferSize);

        if (dwRetVal == ERROR_BUFFER_OVERFLOW)
        {
            buffer.resize(bufferSize);
            pAdapterAddresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
            dwRetVal = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, pAdapterAddresses, &bufferSize);
        }

        if (dwRetVal == NO_ERROR)
        {
            for (PIP_ADAPTER_ADDRESSES pAdapter = pAdapterAddresses; pAdapter != nullptr && !local; pAdapter = pAdapter->Next)
            {
                for (PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pAdapter->FirstUnicastAddress; pUnicast != nullptr && !local; pUnicast = pUnicast->Next)
                {
                    sockaddr* sa = pUnicast->Address.lpSockaddr;

                    char ipString[INET6_ADDRSTRLEN];
                    if (sa->sa_family == AF_INET && addr.is_v4())
                    {
                        sockaddr_in* pSockAddrV4 = reinterpret_cast<sockaddr_in*>(sa);
                        local = addr.to_v4() == boost::asio::ip::address_v4(ntohl(pSockAddrV4->sin_addr.s_addr));
                    }
                    else if (pUnicast->Address.lpSockaddr->sa_family == AF_INET6)
                    {
                        sockaddr_in6* pSockAddrV6 = reinterpret_cast<sockaddr_in6*>(sa);
                        boost::asio::ip::address_v6::bytes_type bytes;
                        std::memcpy(bytes.data(), pSockAddrV6->sin6_addr.s6_addr, 16);
                        local = addr.to_v6() == boost::asio::ip::address_v6(bytes, pSockAddrV6->sin6_scope_id);
                    }
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

    void make_udp_traverse(boost::asio::yield_context yield, checkup mode, traverse& pass) noexcept(false)
    {
        _trc_ << "making traverse for udp...";

        auto mapper = network::create_udp_socket(m_io, m_bind.udp);
        auto binding = exec_udp_binding(yield, mapper, m_stun.udp, m_stun.udp);

        pass.udp.force = firewall { false, true, false, false, firewall::independent, firewall::independent };
        pass.udp.inner = m_bind.udp;
        pass.udp.outer = binding.mapped_endpoint();

        if (!cache::get(protocol::udp, m_stun.udp, pass.udp))
        {
            auto changed_full = binding.changed_endpoint();
            auto changed_addr = endpoint{ changed_full.address, m_stun.udp.port };
            auto changed_port = endpoint{ m_stun.udp.address, changed_full.port };

            bool refresh = true;

            if (!colocated(pass.udp.inner, pass.udp.outer))
            {
                pass.udp.force.nat = true;
                pass.udp.force.hairpin = false;
                pass.udp.force.variable_address = false;
                pass.udp.force.random_port = pass.udp.inner.port != pass.udp.outer.port;
                pass.udp.force.mapping = firewall::independent;
                pass.udp.force.filtering = firewall::address_and_port_dependent;

                if (mode != checkup::simple)
                {
                    try
                    {
                        _trc_ << "first mapping test...";

                        auto first_endpoint = exec_udp_binding(yield, mapper, changed_full, changed_full).mapped_endpoint();
                        if (first_endpoint == pass.udp.outer)
                        {
                            pass.udp.force.mapping = firewall::independent;
                        }
                        else
                        {
                            _trc_ << "second mapping test...";

                            auto second_endpoint = exec_udp_binding(yield, mapper, changed_addr, changed_addr).mapped_endpoint();
                            if (second_endpoint == pass.udp.outer)
                            {
                                pass.udp.force.mapping = firewall::port_dependent;
                            }
                            else if (second_endpoint == first_endpoint)
                            {
                                pass.udp.force.mapping = firewall::address_dependent;
                            }
                            else
                            {
                                pass.udp.force.mapping = firewall::address_and_port_dependent;
                            }

                            if (second_endpoint.address != pass.udp.outer.address || second_endpoint.address != first_endpoint.address)
                            {
                                pass.udp.force.variable_address = true;
                            }
                        }
                    }
                    catch(const std::exception& ex)
                    {
                        if (mode == checkup::strict)
                            throw;

                        refresh = false;
                        _wrn_ << ex.what();
                    }
                }

                try
                {
                    _trc_ << "hairpin test...";

                    exec_udp_binding(yield, mapper, pass.udp.outer, pass.udp.outer, 0, 1400);
                    pass.udp.force.hairpin = true;
                }
                catch(const plexus::timeout_error&) {}
            }

            if (mode != checkup::simple)
            {
                auto filter = plexus::network::create_udp_socket(m_io, endpoint { m_bind.udp.address, 0 });
                try
                {
                    _trc_ << "first filtering test...";

                    exec_udp_binding(yield, filter, m_stun.udp, changed_full, flag::change_address | flag::change_port, 1400);
                    pass.udp.force.filtering = firewall::independent;
                }
                catch(const std::exception&)
                {
                    try
                    {
                        _trc_ << "second filtering test...";

                        exec_udp_binding(yield, filter, m_stun.udp, changed_addr, flag::change_address, 1400);
                        pass.udp.force.filtering = firewall::port_dependent;
                    }
                    catch(const std::exception&)
                    {
                        try
                        {
                            _trc_ << "third filtering test...";

                            exec_udp_binding(yield, filter, m_stun.udp, changed_port, flag::change_port, 1400);
                            pass.udp.force.filtering = firewall::address_dependent;
                        }
                        catch(const std::exception&) {}
                    }
                }
            }

            if (refresh)
                cache::set(protocol::udp, m_stun.udp, pass.udp);
        }

        _inf_ << "udp traverse: inner=" << pass.udp.inner << " outer=" << pass.udp.outer << " force=" << pass.udp.force;
    }

    void make_tcp_traverse(boost::asio::yield_context yield, checkup mode, traverse& pass) noexcept(false)
    {
        _trc_ << "making traverse for tcp...";

        auto binding = exec_tcp_binding(yield, m_bind.tcp, m_stun.tcp);

        pass.tcp.force = firewall { false, true, false, false, firewall::independent, firewall::independent };
        pass.tcp.inner = m_bind.tcp;
        pass.tcp.outer = binding.mapped_endpoint();

        if (!cache::get(protocol::tcp, m_stun.tcp, pass.tcp))
        {
            bool refresh = true;
 
            if (!colocated(pass.tcp.inner, pass.tcp.outer))
            {
                pass.tcp.force.nat = true;
                pass.tcp.force.hairpin = false;
                pass.tcp.force.variable_address = false;
                pass.tcp.force.random_port = pass.tcp.inner.port != pass.tcp.outer.port;
                pass.tcp.force.filtering = firewall::address_and_port_dependent;
                pass.tcp.force.mapping = firewall::independent;

                if (mode != checkup::simple)
                {
                    auto changed_full = binding.changed_endpoint();
                    auto changed_addr = endpoint{ changed_full.address, m_stun.udp.port };

                    try
                    {
                        _trc_ << "first mapping test...";

                        auto first_endpoint = exec_tcp_binding(yield, m_bind.tcp, changed_full).mapped_endpoint();
                        if (first_endpoint == pass.tcp.outer)
                        {
                            pass.tcp.force.mapping = firewall::independent;
                        }
                        else
                        {
                            _trc_ << "second mapping test...";

                            auto second_endpoint = exec_tcp_binding(yield, m_bind.tcp, changed_addr).mapped_endpoint();
                            if (second_endpoint == pass.tcp.outer)
                            {
                                pass.tcp.force.mapping = firewall::port_dependent;
                            }
                            else if (second_endpoint == first_endpoint)
                            {
                                pass.tcp.force.mapping = firewall::address_dependent;
                            }
                            else
                            {
                                pass.tcp.force.mapping = firewall::address_and_port_dependent;
                            }

                            if (second_endpoint.address != pass.tcp.outer.address || second_endpoint.address != first_endpoint.address)
                            {
                                pass.tcp.force.variable_address = true;
                            }
                        }
                    }
                    catch(const std::exception& ex)
                    {
                        if (mode == checkup::strict)
                            throw;

                        refresh = false;
                        _wrn_ << ex.what();
                    }
                }

                try
                {
                    _trc_ << "hairpin test...";

                    auto self = network::create_tcp_socket(m_io, m_bind.tcp, pass.tcp.outer);
                    self->connect(yield, 1400);
                    self->shutdown();

                    pass.tcp.force.hairpin = true;
                }
                catch(const std::exception&) { }
            }

            if (refresh)
                cache::set(protocol::tcp, m_stun.tcp, pass.tcp);
        }

        _inf_ << "tcp traverse: inner=" << pass.tcp.inner << " outer=" << pass.tcp.outer << " force=" << pass.tcp.force;
    }

public:

    traverse make_traverse(boost::asio::yield_context yield, protocol proto, checkup mode) noexcept(false) override
    {
        traverse pass;

        if (mode == checkup::noneed)
        {
            pass.udp.force = firewall { false, true, false, false, firewall::independent, firewall::independent };
            pass.udp.outer = detect_outgoing_endpoint(m_bind.udp);
            pass.udp.inner = pass.udp.outer;

            _inf_ << "udp traverse: from=" << pass.udp.outer;

            if (proto != protocol::udp)
            {
                pass.tcp.force = firewall { false, true, false, false, firewall::independent, firewall::independent };
                pass.tcp.outer = detect_outgoing_endpoint(m_bind.tcp);
                pass.tcp.inner = pass.tcp.outer;

                _inf_ << "tcp traverse: from=" << pass.tcp.outer;
            }

            return pass;
        }

        if (!m_stun.udp.address.is_unspecified())
        {
            try
            {
                make_udp_traverse(yield, mode, pass);
            }
            catch(const std::exception& ex)
            {
                pass.udp.outer = endpoint{};
                _wrn_ << "can't make udp traverse: " << ex.what();
            }
        }

        if (!m_stun.tcp.address.is_unspecified() && proto != protocol::udp)
        {
            try
            {
                make_tcp_traverse(yield, mode, pass);
            }
            catch(const std::exception& ex)
            {
                pass.tcp.outer = endpoint{};
                _wrn_ << "can't make tcp traverse: " << ex.what();
            }
        }

        return pass;
    }
};

}

std::shared_ptr<plexus::stun_client> create_stun_client(boost::asio::io_context& io, const location& stun, const location& bind) noexcept(true)
{
    return std::make_shared<plexus::stun::client_impl>(io, stun, bind);
}

}
