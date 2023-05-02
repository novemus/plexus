/*
 * Copyright (c) 2022 Novemus Band. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 */

#include <future>
#include <iostream>
#include <boost/system/system_error.hpp>
#include <boost/test/unit_test.hpp>
#include "../network.h"
#include "../utils.h"

BOOST_AUTO_TEST_CASE(sync_udp_exchange)
{
    const boost::asio::ip::udp::endpoint lep(boost::asio::ip::address::from_string("127.0.0.1"), 1234);
    const boost::asio::ip::udp::endpoint rep(boost::asio::ip::address::from_string("127.0.0.1"), 4321);

    auto lend = plexus::network::create_udp_transport(lep);
    auto rend = plexus::network::create_udp_transport(rep);

    wormhole::mutable_buffer out("plexus");
    wormhole::mutable_buffer in(512);

    BOOST_REQUIRE_NO_THROW(lend->send(rep, out));

    BOOST_REQUIRE_NO_THROW(BOOST_REQUIRE_EQUAL(out.size(), rend->receive(lep, in)));
    BOOST_REQUIRE_EQUAL(std::memcmp(out.data(), in.data(), out.size()), 0);

    BOOST_REQUIRE_NO_THROW(rend->send(lep, out));

    BOOST_REQUIRE_NO_THROW(BOOST_REQUIRE_EQUAL(out.size(), lend->receive(rep, in)));
    BOOST_REQUIRE_EQUAL(std::memcmp(out.data(), in.data(), out.size()), 0);

    BOOST_REQUIRE_THROW(lend->receive(rep, in), boost::system::system_error);
}

BOOST_AUTO_TEST_CASE(async_udp_exchange)
{
    const boost::asio::ip::udp::endpoint lep(boost::asio::ip::address::from_string("127.0.0.1"), 1234);
    const boost::asio::ip::udp::endpoint rep(boost::asio::ip::address::from_string("127.0.0.1"), 4321);

    auto lend = plexus::network::create_udp_transport(lep);
    auto rend = plexus::network::create_udp_transport(rep);

    auto work = [](std::shared_ptr<plexus::network::udp> udp, const boost::asio::ip::udp::endpoint& peer)
    {
        wormhole::mutable_buffer out("plexus");
        wormhole::mutable_buffer in(512);

        BOOST_REQUIRE_NO_THROW(udp->send(peer, out));
        BOOST_REQUIRE_NO_THROW(udp->send(peer, out));
        BOOST_REQUIRE_NO_THROW(udp->send(peer, out));

        BOOST_REQUIRE_NO_THROW(BOOST_REQUIRE_EQUAL(out.size(), udp->receive(peer, in)));
        BOOST_REQUIRE_EQUAL(std::memcmp(out.data(), in.data(), out.size()), 0);

        BOOST_REQUIRE_NO_THROW(BOOST_REQUIRE_EQUAL(out.size(), udp->receive(peer, in)));
        BOOST_REQUIRE_EQUAL(std::memcmp(out.data(), in.data(), out.size()), 0);

        BOOST_REQUIRE_NO_THROW(BOOST_REQUIRE_EQUAL(out.size(), udp->receive(peer, in)));
        BOOST_REQUIRE_EQUAL(std::memcmp(out.data(), in.data(), out.size()), 0);
    };

    auto l = std::async(std::launch::async, work, lend, rep);
    auto r = std::async(std::launch::async, work, rend, lep);

    BOOST_REQUIRE_NO_THROW(l.wait());
    BOOST_REQUIRE_NO_THROW(r.wait());
}
