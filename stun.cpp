#include <iostream>
#include <sstream>
#include <iomanip>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <netinet/in.h>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include "network.h"
#include "features.h"

namespace plexus { namespace features {

struct endpoint
{
    std::string address;
    unsigned short port;
};

class stun_message : public network::udp_client::transfer
{
    static const size_t MESSAGE_LENGTH_OFFSET = 2;
    static const size_t TRANSACTION_ID_OFFSET = 4;
    static const size_t TRANSACTION_ID_LENGTH = 16;
    static const size_t MESSAGE_HEADER_SIZE = 20;
    static const size_t MAX_MESSAGE_SIZE = 548;

public:

    stun_message(const endpoint& server, unsigned char flags)
        : network::udp_client::transfer(server, std::initializer_list<unsigned char>{
            0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, flags 
            })
    {
        boost::uuids::uuid id = boost::uuids::random_generator()();
        std::memcpy(buffer.data() + TRANSACTION_ID_OFFSET, id.data, TRANSACTION_ID_LENGTH);
    }

    stun_message() : network::udp_client::transfer(MAX_MESSAGE_SIZE)
    {
    }
    
    boost::uuids::uuid id() const
    {
        boost::uuids::uuid id;
        std::memcpy(id.data, buffer.data() + TRANSACTION_ID_OFFSET, TRANSACTION_ID_LENGTH);
        return id;
    }

    size_t size() const
    {
        return MESSAGE_HEADER_SIZE + ntohs(*(unsigned short*)(buffer.data() + MESSAGE_LENGTH_OFFSET));
    }

    endpoint source_endpoint() const
    {
    }

    endpoint changed_endpoint() const
    {
    }

    endpoint mapped_endpoint() const
    {
    }

    std::string dump() const
    {
        std::stringstream ss;
        ss << std::hex;
        for (size_t i = 0; i < std::min(buffer.size(), size()); ++i)
            ss << std::setw(2) << std::setfill('0') << (int)buffer[i];
        return ss.str();
    }
};
typedef std::shared_ptr<stun_message> stun_message_ptr;

/* firewall testing

*** legend ***

fa - first address of stun server
sa - second address of stun server
fp - first port of stun server
sp - second port of stun server
ma - mapped address
mp - mapped port
ca - state of change address flag
cp - state of change port flag
nt - request for nat test
mt* - requests for mapping test
ft* - requests for filtering test
ht - request for hairpin test

*** algorithm ***

nt: fa, fp, ca=0, cp=0
    if mapped endpoint is equal to the local endpoint, then there is no nat, otherwise make "mt1", "ft1", "ht" tests and check if the mapping retains port
mt1: sa, sp, ca=0, cp=0
    if mapped endpoint is equal to the first "nt" test endpoint, then there is independent mapping, otherwise, make "mt2" test and check if address mapping is immutable
mt2: sa, fp, ca=0, cp=0
    if mapped endpoint is equal to the "mt1" test endpoint, then there is address dependent mapping, otherwise there is address and port dependent mapping
ft1: fa, fp, ca=1, cp=1
    if response will be received, then there is endpoint independent filtering, otherwise make "ft2" test
ft2: fa, fp, ca=0, cp=1
    if response will be received, then there is address dependent filtering, otherwise there is address and port dependent filtering
ht: ma, mp, ca=0, cp=0
    if response will be received, then there is hairpin
*/

class stun_network_traverse : public network_traverse
{
    long receive(stun_message_ptr response, long timeout)
    {
        auto timer = [start = boost::posix_time::microsec_clock::universal_time()]()
        {
            return boost::posix_time::microsec_clock::universal_time() - start;
        };

        static const size_t MIN_MESSAGE_SIZE = 20;

        size_t size = m_client->receive(response, timeout).get();
        if (size < MIN_MESSAGE_SIZE || size < response->size())
            throw std::runtime_error("can't receive message");

        return timeout - timer().total_milliseconds();
    }

    long send(stun_message_ptr request, long timeout)
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

    stun_message_ptr exec_binding_request(stun_message_ptr request)
    {
        stun_message_ptr response = std::make_shared<stun_message>();

        long deadline = 100;
        for (int i = 0; i < 9; ++i)
        {
            if (m_trace)
                std::cout << "<<<<< " << request->dump() << std::endl;

            long timeout = send(request, deadline);

            try
            {
                do
                {
                    timeout = receive(response, timeout);

                    if (m_trace)
                        std::cout << ">>>>> " << response->dump() << std::endl;
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

    static const unsigned char CHANGE_ADDRESS_FLAG = 0x04;
    static const unsigned char CHANGE_PORT_FLAG = 0x02;

public:

    stun_network_traverse(const std::string& stun, const std::string& interface, unsigned short port)
        : m_client(network::create_udp_client(interface, port))
    {
    }

    virtual firewall explore_firewall() noexcept(false) override {}
    virtual mapping punch_udp_hole() noexcept(false) override {}

private:

    std::shared_ptr<network::udp_client> m_client;
    bool m_trace = false;
};

}}
