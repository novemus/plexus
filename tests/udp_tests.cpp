#include <future>
#include <iostream>
#include <boost/test/unit_test.hpp>
#include "../network.h"
#include "../utils.h"

typedef plexus::network::endpoint endpoint_t;
typedef plexus::network::udp::transfer transfer_t;
typedef std::shared_ptr<plexus::network::udp::transfer> transfer_ptr;
typedef std::shared_ptr<plexus::network::udp> udp_ptr;

const std::initializer_list<uint8_t> data = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };
const endpoint_t lep = std::make_pair("127.0.0.1", 1234);
const endpoint_t rep = std::make_pair("127.0.0.1", 4321);

BOOST_AUTO_TEST_CASE(simple)
{
    udp_ptr lend = plexus::network::create_udp_channel("127.0.0.1", 1234);
    udp_ptr rend = plexus::network::create_udp_channel("127.0.0.1", 4321);

    transfer_ptr ltr = std::make_shared<transfer_t>(rep, data);
    transfer_ptr rtr = std::make_shared<transfer_t>(data.size());

    auto sent = lend->send(ltr);
    auto recv = rend->receive(rtr);

    BOOST_REQUIRE_EQUAL(sent, recv);
    BOOST_REQUIRE(rtr->remote == lep);
    BOOST_REQUIRE_EQUAL(std::memcmp(ltr->buffer.data(), rtr->buffer.data(), ltr->buffer.size()), 0);

    sent = rend->send(rtr);
    recv = lend->receive(ltr);

    BOOST_REQUIRE_EQUAL(sent, recv);
    BOOST_REQUIRE(ltr->remote == rep);
    BOOST_REQUIRE_EQUAL(std::memcmp(ltr->buffer.data(), rtr->buffer.data(), ltr->buffer.size()), 0);
}
