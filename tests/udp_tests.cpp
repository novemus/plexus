#include <future>
#include <iostream>
#include <boost/system/system_error.hpp>
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

BOOST_AUTO_TEST_CASE(sync_udp_exchange)
{
    udp_ptr lend = plexus::network::create_udp_channel("127.0.0.1", 1234);
    udp_ptr rend = plexus::network::create_udp_channel("127.0.0.1", 4321);

    transfer_ptr ltr = std::make_shared<transfer_t>(rep, data);
    transfer_ptr rtr = std::make_shared<transfer_t>(data.size());

    BOOST_REQUIRE_EQUAL(lend->send(ltr), ltr->buffer.size());
    BOOST_REQUIRE_EQUAL(rend->receive(rtr), ltr->buffer.size());

    BOOST_REQUIRE(rtr->remote == lep);
    BOOST_REQUIRE_EQUAL(std::memcmp(ltr->buffer.data(), rtr->buffer.data(), ltr->buffer.size()), 0);

    BOOST_REQUIRE_EQUAL(rend->send(rtr), rtr->buffer.size());
    BOOST_REQUIRE_EQUAL(lend->receive(ltr), rtr->buffer.size());

    BOOST_REQUIRE(ltr->remote == rep);
    BOOST_REQUIRE_EQUAL(std::memcmp(ltr->buffer.data(), rtr->buffer.data(), ltr->buffer.size()), 0);

    BOOST_REQUIRE_THROW(lend->receive(ltr), boost::system::system_error);
}

BOOST_AUTO_TEST_CASE(async_udp_exchange)
{
    auto work = [](uint16_t port, const endpoint_t& peer)
    {
        udp_ptr udp = plexus::network::create_udp_channel("127.0.0.1", port);
        transfer_ptr reqv = std::make_shared<transfer_t>(peer, data);
        transfer_ptr resp = std::make_shared<transfer_t>(data.size());

        BOOST_REQUIRE_EQUAL(udp->send(reqv), reqv->buffer.size());
        BOOST_REQUIRE_EQUAL(udp->send(reqv), reqv->buffer.size());
        BOOST_REQUIRE_EQUAL(udp->send(reqv), reqv->buffer.size());

        BOOST_REQUIRE_EQUAL(udp->receive(resp), reqv->buffer.size());
        BOOST_REQUIRE(resp->remote == peer);
        BOOST_REQUIRE_EQUAL(std::memcmp(resp->buffer.data(), reqv->buffer.data(), reqv->buffer.size()), 0);
        BOOST_REQUIRE_EQUAL(udp->receive(resp), reqv->buffer.size());
        BOOST_REQUIRE(resp->remote == peer);
        BOOST_REQUIRE_EQUAL(std::memcmp(resp->buffer.data(), reqv->buffer.data(), reqv->buffer.size()), 0);
        BOOST_REQUIRE_EQUAL(udp->receive(resp), reqv->buffer.size());
        BOOST_REQUIRE(resp->remote == peer);
        BOOST_REQUIRE_EQUAL(std::memcmp(resp->buffer.data(), reqv->buffer.data(), reqv->buffer.size()), 0);
    };

    auto l = std::async(std::launch::async, work, 1234, rep);
    auto r = std::async(std::launch::async, work, 4321, lep);

    BOOST_REQUIRE_NO_THROW(l.wait());
    BOOST_REQUIRE_NO_THROW(r.wait());
}
