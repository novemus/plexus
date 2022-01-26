#include "network.h"
#include "features.h"

namespace plexus { namespace features {

class stun_network_traverse : public network_traverse
{
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
    nr - request for nat test
    mr* - requests for mapping test
    fr* - requests for filtering test
    hr - request for hairpin test

    *** algorithm ***

    nr: fa, fp, ca=0, cp=0
        if mapped endpoint is equal to the local endpoint, then there is no nat, otherwise make "mr1", "fr1", "hr" tests and check if the mapping retains port
    mr1: sa, sp, ca=0, cp=0
        if mapped endpoint is equal to the first "nr" test endpoint, then there is independent mapping, otherwise, make "mr2" test and check if address mapping is immutable
    mr2: sa, fp, ca=0, cp=0
        if mapped endpoint is equal to the "mr1" test endpoint, then there is address dependent mapping, otherwise there is address and port dependent mapping
    fr1: fa, fp, ca=1, cp=1
        if response will be received, then there is endpoint independent filtering, otherwise make "fr2" test
    fr2: fa, fp, ca=0, cp=1
        if response will be received, then there is address dependent filtering, otherwise there is address and port dependent filtering
    hr: ma, mp, ca=0, cp=0
        if response will be received, then there is hairpin
    */

public:

    stun_network_traverse(const std::string& stun, const std::string& interface, unsigned short port)
        : m_client(network::create_udp_client(interface, port))
    {
    }
};

}}
