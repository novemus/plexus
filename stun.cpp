#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <array>
#include <netinet/in.h>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include "network.h"
#include "features.h"
#include "utils.h"

namespace plexus { namespace features { namespace stun {

struct endpoint
{
    std::string address;
    uint16_t port;
};

typedef std::array<uint8_t, 16> transaction_id;

const size_t min_message_size = 20;
const size_t max_message_size = 548;

// message types
const uint16_t binding_request = 0x0001;
const uint16_t binding_response = 0x0101;
const uint16_t binding_error_response = 0x0111;

// attributes
const uint16_t mapped_address = 0x0001;
const uint16_t change_request = 0x0003;
const uint16_t source_address = 0x0004;
const uint16_t changed_address = 0x0005;
const uint16_t error_code = 0x0009;
const uint16_t unknown_attributes = 0x000a;
const uint16_t reflected_from = 0x000b;

// flags
const uint8_t ip_v4 = 0x01;
const uint8_t ip_v6 = 0x02;

const uint16_t change_address = 0x04;
const uint16_t change_port = 0x02;


class binding_message : public network::udp_client::transfer
{
    static inline uint8_t rand_char()
    {
        return static_cast<uint8_t>(std::rand() % 256);
    }

    static inline std::initializer_list<uint8_t> build_request_buffer(uint8_t flags)
    {
        return std::initializer_list<uint8_t> {
            0x00, 0x01, 0x00, 0x08, 
            rand_char(), rand_char(), rand_char(), rand_char(),
            rand_char(), rand_char(), rand_char(), rand_char(),
            rand_char(), rand_char(), rand_char(), rand_char(),
            rand_char(), rand_char(), rand_char(), rand_char(),
            0x00, 0x03, 0x00, 0x04, 
            0x00, 0x00, 0x00, flags 
            };
    }

    endpoint fetch_endpoint(uint16_t type) const
    {
        const uint8_t* ptr = &buffer[20];
        const uint8_t* end = buffer.data() + size();

        while (ptr + 4 < end)
        {
            uint16_t attribute = ntohs(*(uint16_t*)ptr); ptr += 2;
            uint16_t length = ntohs(*(uint16_t*)ptr); ptr += 2;

            if (attribute == type)
            {
                if (ptr + length > end)
                    throw std::runtime_error("wrong endpoint data");

                if (ptr[1] == stun::ip_v4)
                {
                    if (length != 8u)
                        throw std::runtime_error("wrong endpoint data");

                    return endpoint{
                        utils::format("%d.%d.%d.%d", ptr[4], ptr[5], ptr[6], ptr[7]),
                        ntohs(uint16_t(ptr[2]) << 8 | uint16_t(ptr[3]))
                    };
                }
                else if (ptr[1] == stun::ip_v6)
                {
                    if (length != 20u)
                        throw std::runtime_error("wrong endpoint data");

                    return endpoint{
                        utils::format("%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d", ptr[4], ptr[5], ptr[6], ptr[7], ptr[8], ptr[9], ptr[10], ptr[11], ptr[12], ptr[13], ptr[14], ptr[15], ptr[16], ptr[17], ptr[18], ptr[19]),
                        ntohs(uint16_t(ptr[2]) << 8 | uint16_t(ptr[3]))
                    };
                }
            }

            ptr += length;
        }

        return endpoint{};
    }

public:

    binding_message(const std::string& address, uint16_t port, uint8_t flags)
        : transfer(address, std::to_string(port), build_request_buffer(flags))
    {
    }

    binding_message(size_t size) : transfer(size)
    {
    }
    
    transaction_id id() const
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
        return ntohs(uint16_t(buffer[0]) << 8 | uint16_t(buffer[1]));
    }

    uint16_t size() const
    {
        return 20u + ntohs(uint16_t(buffer[2]) << 8 | uint16_t(buffer[3]));
    }

    endpoint source_endpoint() const
    {
        return fetch_endpoint(stun::source_address);
    }

    endpoint changed_endpoint() const
    {
        return fetch_endpoint(stun::changed_address);
    }

    endpoint mapped_endpoint() const
    {
        return fetch_endpoint(stun::mapped_address);
    }
};

typedef std::shared_ptr<binding_message> binding_message_ptr;

}

using namespace stun;

std::ostream& operator<<(std::ostream& stream, binding_message_ptr message)
{
    if (message)
    {
        size_t size = std::min((size_t)message->size(), message->buffer.size());
        for (size_t i = 0; i < size; ++i)
        {
            stream << std::setw(2) << std::setfill('0') << (int)message->buffer[i];
        }
    }
    return stream;
}

/* firewall testing

*** legend ***

NAT_TEST - nat test
MAPPING_TEST_* - mapping tests
FILERING_TEST_* - filtering tests
HAIRPIN_TEST - hairpin test

SA - source ip address of stun server
CA - canged ip address of stun server
SP - source port of stun server
CP - canged port of stun server
MA - mapped address
MP - mapped port
AF - state of change address flag
PF - state of change port flag

*** algorithm ***

NAT_TEST: SA, SP, AF=0, PF=0
    if mapped endpoint is equal to the local endpoint, then there is no NAT, otherwise make "MAPPING_TEST_1", "FILERING_TEST_1", "HAIRPIN_TEST" and check if the mapping retains port
MAPPING_TEST_1: CA, CP, AF=0, PF=0
    if mapped endpoint is equal to the "NAT_TEST" endpoint, then there is independent mapping, otherwise, make "MAPPING_TEST_2" and check if address mapping is immutable
MAPPING_TEST_2: CA, SP, AF=0, PF=0
    if mapped endpoint is equal to the "MAPPING_TEST_1" endpoint, then there is address dependent mapping, otherwise there is address and port dependent mapping
FILERING_TEST_1: SA, SP, AF=1, PF=1
    if response will be received, then there is endpoint independent filtering, otherwise make "FILERING_TEST_2"
FILERING_TEST_2: SA, SP, AF=0, PF=1
    if response will be received, then there is address dependent filtering, otherwise there is address and port dependent filtering
HAIRPIN_TEST: MA, MP, AF=0, PF=0
    if response will be received, then there is hairpin
*/

class stun_network_traverse : public network_traverse
{
    int64_t receive(binding_message_ptr response, int64_t timeout)
    {
        auto timer = [start = boost::posix_time::microsec_clock::universal_time()]()
        {
            return boost::posix_time::microsec_clock::universal_time() - start;
        };

        size_t size = m_client->receive(response, timeout).get();
        if (size < stun::min_message_size || size < response->size())
            throw std::runtime_error("can't receive message");

        return timeout - timer().total_milliseconds();
    }

    int64_t send(binding_message_ptr request, int64_t timeout)
    {
        auto timer = [start = boost::posix_time::microsec_clock::universal_time()]()
        {
            return boost::posix_time::microsec_clock::universal_time() - start;
        };

        size_t size = m_client->send(request, timeout).get();
        if (size < request->buffer.size())
            throw std::runtime_error("can't send message");

        return timeout - timer().total_milliseconds();
    }

    binding_message_ptr exec_binding_request(binding_message_ptr request)
    {
        binding_message_ptr response = std::make_shared<binding_message>(stun::max_message_size);

        int64_t deadline = 100;
        for (int i = 0; i < 9; ++i)
        {
            if (m_trace)
                std::cout << "<<<<< " << request << std::endl;

            int64_t timeout = send(request, deadline);

            try
            {
                do
                {
                    timeout = receive(response, timeout);

                    if (m_trace)
                        std::cout << ">>>>> " << response << std::endl;
                } 
                while (request->id() != response->id());

                return response;
            }
            catch(const network::timeout_error&)
            {
                deadline = std::min(1600l, deadline * 2);
            }
        }

        throw network::timeout_error();
    }

public:

    stun_network_traverse(const std::string& stun, const std::string& interface, uint16_t port)
        : m_client(network::create_udp_client(interface, port))
    {
        std::srand(std::time(nullptr));
    }

    virtual firewall explore_firewall() noexcept(false) override {}
    virtual mapping punch_udp_hole() noexcept(false) override {}

private:

    std::shared_ptr<network::udp_client> m_client;
    bool m_trace = false;
};

network_traverse* create_stun_network_traverse(const std::string& stun, const std::string& interface)
{
    return new stun_network_traverse(stun, interface, 5000);
}

}}
