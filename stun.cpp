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

INIT_TEST: SA, SP, AF=0, PF=0
    Acquire endpoints of the stun server.
FILERING_TEST_1: SA, SP, AF=1, PF=1
    Tell the stun server to reply from changed address and changed port.
    If response will be received, then there is the endpoint independent filtering,
    otherwise go to the FILERING_TEST_2 test
FILERING_TEST_2: SA, SP, AF=0, PF=1
    Tell the stun server to reply from source address and changed port.
    if response will be received, then there is the address dependent filtering,
    otherwise there is address and port dependent filtering
NAT_TEST: CA, CP, AF=0, PF=0
    Acquire mapped endpoint from source address and source port of the stun server. We can't
    use mapped endpoint from INIT_TEST because fairwall can drop binding on filtering tests
    If mapped endpoint is equal to the local endpoint, then there is no NAT,
    otherwise check if the mapping retains port and go to the MAPPING_TEST_1 test
MAPPING_TEST_1: CA, CP, AF=0, PF=0
    Acquire mapped endpoint from changed address and changed port of the stun server.
    If mapped endpoint is equal to the NAT_TEST endpoint, then there is the independent mapping,
    otherwise check if address is immutable and go to the HAPPING_TEST_2 test
MAPPING_TEST_2: CA, SP, AF=0, PF=0
    Acquire mapped endpoint from changed address and source port of the stun server.
    if mapped endpoint is equal to the "MAPPING_TEST_1" endpoint, then there is the address dependent mapping,
    otherwise there is address and port dependent mapping.
HAIRPIN_TEST: MA, MP, AF=0, PF=0
    Send request to the mapped endpoint.
    If response will be received, then there is a hairpin.
*/

namespace plexus { namespace features { namespace stun {

typedef std::array<uint8_t, 16> transaction_id;
typedef std::pair<std::string, uint16_t> endpoint;

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
        size_t size = std::min((size_t)message->size(), message->buffer.size());
        for (size_t i = 0; i < size; ++i)
        {
            stream << std::setw(2) << std::setfill('0') << (int)message->buffer[i];
        }
    }
    return stream;
}

class stun_network_traverse : public network_traverse
{
    inline void send(message_ptr request, int64_t timeout)
    {
        if (m_trace)
            std::cout << ">>>>> " << request << std::endl;

        size_t size = m_client->send(request, timeout).get();
        if (size < request->buffer.size())
            throw std::runtime_error("can't send message");
    }

    inline void receive(message_ptr response, int64_t timeout)
    {
        size_t size = m_client->receive(response, timeout).get();
        if (size < msg::min_size || size < response->size())
            throw std::runtime_error("can't receive message");

        if (m_trace)
            std::cout << "<<<<< " << response << std::endl;
    }

    message_ptr exec_binding_request(const std::string& address, uint16_t port, uint8_t flags = 0, int64_t deadline = 4600)
    {
        auto timer = [start = boost::posix_time::microsec_clock::universal_time()]()
        {
            return boost::posix_time::microsec_clock::universal_time() - start;
        };

        message_ptr request = std::make_shared<message>(address, port, flags);
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

                        std::cout << "mapped_endpoint=" << me.first << ":" << me.second << std::endl
                                  << "source_endpoint=" << se.first << ":" << se.second << std::endl
                                  << "changed_endpoint=" << ce.first << ":" << ce.second << std::endl;
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
        
        throw network::timeout_error();
    }

public:

    stun_network_traverse(const std::string& stun_server, const std::string& local_address, uint16_t local_port)
        : m_client(network::create_udp_client(local_address, local_port))
        , m_stun_server(stun_server)
        , m_local_address(local_address)
        , m_local_port(local_port)
    {
        std::srand(std::time(nullptr));
    }

    firewall explore_firewall() noexcept(false) override
    {
        firewall state = {0};

        std::cout << "init test..." << std::endl;

        message_ptr resp = exec_binding_request(m_stun_server, stun::default_port);
        endpoint se = resp->source_endpoint();
        endpoint ce = resp->changed_endpoint();

        std::cout << "first filtering test..." << std::endl;
        try
        {
            exec_binding_request(se.first, se.second, flag::change_address | flag::change_port);
            state.inbound_binding = firewall::independent;
        }
        catch(const network::timeout_error&)
        {
            std::cout << "second filtering test..." << std::endl;
            try
            {
                exec_binding_request(se.first, se.second, flag::change_port);
                state.inbound_binding = firewall::address_dependend;
            }
            catch(const network::timeout_error&)
            {
                state.inbound_binding = firewall::address_port_dependend;
            }
        }

        std::cout << "nat test..." << std::endl;
        endpoint me = exec_binding_request(se.first, se.second)->mapped_endpoint();

        if (me.first != m_local_address || me.second != m_local_port)
        {
            state.nat = 1;
            state.retainable_port = me.second == m_local_port ? 1 : 0;

            std::cout << "first mapping test..." << std::endl;
            endpoint fme = exec_binding_request(ce.first, ce.second)->mapped_endpoint();

            if (fme == me)
            {
                state.outbound_binding = firewall::independent;
            }
            else
            {
                if (fme.first == me.first)
                {
                    state.immutable_address = 1;
                }
                
                std::cout << "second mapping test..." << std::endl;
                endpoint sme = exec_binding_request(ce.first, se.second)->mapped_endpoint();

                state.outbound_binding = sme == fme ? firewall::address_dependend : firewall::address_port_dependend;
            }

            std::cout << "hairpin test..." << std::endl;
            try
            {
                exec_binding_request(me.first, me.second, 0, 1600);
                state.hairpin = 1;
            }
            catch(const network::timeout_error&) { }
        }

        std::cout << "\nfirewall:" << std::endl
                  << "\tnat: " << (state.nat ? "true" : "false") << std::endl
                  << "\toutbound binding: 0x" << std::hex << state.outbound_binding << std::endl
                  << "\tinbound binding:  0x" << std::hex << state.inbound_binding << std::endl
                  << "\tretainable port: " << (state.retainable_port ? "true" : "false") << std::endl
                  << "\timmutable address: " << (state.retainable_port ? "true" : "false") << std::endl
                  << "\thairpin: " << (state.hairpin ? "true" : "false") << std::endl;

        return state;
    }

    endpoint punch_udp_hole() noexcept(false) override
    {
        message_ptr response = exec_binding_request(m_stun_server, stun::default_port);
        return response->mapped_endpoint();
    }

private:

    std::shared_ptr<network::udp_client> m_client;
    std::string m_stun_server;
    std::string m_local_address;
    uint16_t m_local_port;
    bool m_trace = false;
};

network_traverse* create_network_traverse(const std::string& stun_server, const std::string& local_address, uint16_t local_port)
{
    return new stun_network_traverse(stun_server, local_address, local_port);
}

}}
