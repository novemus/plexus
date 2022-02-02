#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <array>
#include <netinet/in.h>
#include <boost/asio/error.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include "network.h"
#include "features.h"
#include "utils.h"
#include "log.h"

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

namespace plexus { namespace network { namespace stun {

typedef std::array<uint8_t, 16> transaction_id;
typedef std::pair<std::string, uint16_t> endpoint;
typedef std::shared_ptr<network::udp_client> udp_client_ptr;

const uint16_t default_port = 3478u;

namespace msg {
    const size_t min_size = 20;
    const size_t max_size = 548;
    const uint16_t binding_request = 0x0001;
    const uint16_t binding_response = 0x0101;
    const uint16_t binding_error_response = 0x0111;
}

namespace attr {
    const uint16_t mapped_address = 0x0001;
    const uint16_t change_request = 0x0003;
    const uint16_t source_address = 0x0004;
    const uint16_t changed_address = 0x0005;
    const uint16_t error_code = 0x0009;
    const uint16_t unknown_attributes = 0x000a;
    const uint16_t reflected_from = 0x000b;
}

namespace flag {
    const uint8_t ip_v4 = 0x01;
    const uint8_t ip_v6 = 0x02;
    const uint8_t change_address = 0x04;
    const uint8_t change_port = 0x02;
}

class message : public network::udp_client::transfer
{
    inline static uint16_t read_short(const uint8_t* array, size_t offset = 0)
    {
        return ntohs(*(uint16_t*)(array + offset));
    }

    inline static uint8_t rand_byte()
    {
        return (uint8_t)std::rand();
    }

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

    message(const std::string& address, uint16_t port, uint8_t flags = 0)
        : transfer(address, std::to_string(port))
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

}

using namespace stun;

std::ostream& operator<<(std::ostream& stream, const message_ptr& message)
{
    if (message)
    {
        std::stringstream out;
        size_t size = std::min((size_t)message->size(), message->buffer.size());
        for (size_t i = 0; i < size; ++i)
        {
            out << std::setw(2) << std::setfill('0') << std::hex << (int)message->buffer[i];
        }
        stream << out.str();
    }
    return stream;
}

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

class stun_session
{
    inline void send(message_ptr request, int64_t timeout)
    {
        _trc_ << request->host << ":" << request->service << " <<<<< " << request;

        size_t size = m_udp->send(request, timeout).get();
        if (size < request->buffer.size())
            throw std::runtime_error("can't send message");
    }

    inline void receive(message_ptr response, int64_t timeout)
    {
        size_t size = m_udp->receive(response, timeout).get();
        if (size < msg::min_size || size < response->size())
            throw std::runtime_error("can't receive message");

        _trc_ << response->host << ":" << response->service << " >>>>> " << response;
    }

public:

    stun_session(const endpoint& local)
        : m_udp(create_udp_client(local.first, local.second))
    {
    }

    message_ptr exec_binding_request(const endpoint& stun, uint8_t flags = 0, int64_t deadline = 4600)
    {
        auto timer = [start = boost::posix_time::microsec_clock::universal_time()]()
        {
            return boost::posix_time::microsec_clock::universal_time() - start;
        };

        message_ptr request = std::make_shared<message>(stun.first, stun.second, flags);
        message_ptr response = std::make_shared<message>(msg::max_size);

        int64_t timeout = 200;
        do
        {
            send(request, timeout);

            try
            {
                do
                {
                    receive(response, timeout);
                } 
                while (request->transaction() != response->transaction());

                switch(response->type())
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

                timeout = std::min(1600l, timeout * 2);
            }
        } 
        while (timer().total_milliseconds() < deadline);
        
        throw timeout_error();
    }

private:

    udp_client_ptr m_udp;
};

class classic_stun_client : public stun_client
{
    endpoint m_stun_server;
    endpoint m_for_mapping;
    endpoint m_for_filtering;
    stun_session m_mapping_tester;
    stun_session m_filtering_tester;

public:

    classic_stun_client(const std::string& stun_server, const std::string& local_address, uint16_t local_port)
        : m_stun_server(endpoint{stun_server, stun::default_port})
        , m_for_mapping(endpoint{local_address, local_port})
        , m_for_filtering(endpoint{local_address, local_port + 1})
        , m_mapping_tester(m_for_mapping)
        , m_filtering_tester(m_for_filtering)
    {
        std::srand(std::time(nullptr));
    }

    traverse explore_network() noexcept(false) override
    {
        traverse state = {0};

        _dbg_ << "nat test...";
        message_ptr response = m_mapping_tester.exec_binding_request(m_stun_server);

        endpoint mapped = response->mapped_endpoint();
        endpoint source = response->source_endpoint();
        endpoint changed = response->changed_endpoint();

        if (mapped != m_for_mapping)
        {
            state.nat = 1;
            state.random_port = mapped.second != m_for_mapping.second ? 1 : 0;
            
            _dbg_ << "first mapping test...";
            endpoint fst_mapped = m_mapping_tester.exec_binding_request(changed)->mapped_endpoint();

            state.variable_address = mapped.first != fst_mapped.first ? 1 : 0;

            if (fst_mapped == mapped)
            {
                state.mapping = binding::independent;
            }
            else
            {
                _dbg_ << "second mapping test...";
                endpoint snd_mapped = m_mapping_tester.exec_binding_request(endpoint{changed.first, source.second})->mapped_endpoint();

                state.mapping = snd_mapped == fst_mapped ? binding::address_dependent : binding::address_and_port_dependent;
            }
        }

        _dbg_ << "hairpin test...";
        try
        {
            m_mapping_tester.exec_binding_request(mapped, 0, 1400);
            state.hairpin = 1;
        }
        catch(const timeout_error&) { }

        _dbg_ << "first filtering test...";
        try
        {
            m_filtering_tester.exec_binding_request(m_stun_server, flag::change_address | flag::change_port, 1400);
            state.filtering = binding::independent;
        }
        catch(const timeout_error&)
        {
            _dbg_ << "second filtering test...";
            try
            {
                m_filtering_tester.exec_binding_request(m_stun_server, flag::change_port, 1400);
                state.filtering = binding::address_dependent;
            }
            catch(const timeout_error&)
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
        _dbg_ << "punch udp hole...";
        return m_mapping_tester.exec_binding_request(m_stun_server)->mapped_endpoint();
    }
};

stun_client* create_stun_client(const std::string& stun_server, const std::string& local_address, uint16_t local_port)
{
    return new classic_stun_client(stun_server, local_address, local_port);
}

}}
