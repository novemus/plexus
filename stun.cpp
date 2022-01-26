#include <cstdlib>
#include <ctime>
#include <cstring>
#include <boost/system/system_error.hpp>
#include <boost/asio/error.hpp>
#include "network.h"
#include "features.h"

#define RAND static_cast<unsigned char>(std::rand() % 256)

namespace plexus { namespace features {

class stun_network_traverse : public network_traverse
{
    typedef network::udp_client::transfer transfer;
    typedef network::udp_client::transfer_ptr transfer_ptr;

    std::shared_ptr<network::udp_client> m_client;

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
   
    struct endpoint
    {
        std::string address;
        std::string port;
    };

    struct binding_response
    {
        endpoint mapped_endpoint;
        endpoint source_endpoint;
        endpoint changed_endpoint;
    };

    const unsigned char CHANGE_ADDRESS = 0b00000100;
    const unsigned char CHANGE_PORT = 0b00000010;

    binding_response exec_binding_request(const endpoint& dest, unsigned char flags = 0)
    {
        transfer_ptr request = std::make_shared<transfer>(dest.address, dest.port, std::initializer_list<unsigned char>{
                0x00, 0x01, 0x00, 0x08,
                RAND, RAND, RAND, RAND, RAND, RAND, RAND, RAND, RAND, RAND, RAND, RAND, RAND, RAND, RAND, RAND,
                0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, flags
                });
        transfer_ptr response = std::make_shared<transfer>(576);

        int timeout = 100;
        for(int i = 0; i < 9; ++i)
        {
            m_client->send(request, timeout).wait();

            try
            {
                while (true)
                {
                    m_client->receive(response, timeout).wait();
                    if (std::memcmp(request->buffer.data() + 8, response->buffer.data() + 8, 12) == 0)
                        break;
                }
            }
            catch(const boost::system::system_error& ex)
            {
                if (ex.code() == boost::asio::error::operation_aborted)
                    timeout = std::min(1600, timeout * 2);
                else
                    throw;
            }
        }

        if (std::memcmp(request->buffer.data() + 8, response->buffer.data() + 8, 12) == 0)
            throw std::runtime_error("failed to execute request");
    }

public:

    stun_network_traverse(const std::string& stun, const std::string& interface, unsigned short port)
        : m_client(network::create_udp_client(interface, port))
    {
         std::srand(std::time(nullptr));
    }
};

}}
