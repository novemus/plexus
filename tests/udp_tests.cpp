/*
 * Copyright (c) 2022 Novemus Band. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 */

#include "../network.h"
#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/system/system_error.hpp>
#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_CASE(sync_udp_exchange)
{
    boost::asio::io_service io;
    boost::asio::spawn(io, [&](boost::asio::yield_context yield)
    {
        const boost::asio::ip::udp::endpoint lep(boost::asio::ip::address::from_string("127.0.0.1"), 1234);
        const boost::asio::ip::udp::endpoint rep(boost::asio::ip::address::from_string("127.0.0.1"), 4321);

        auto lend = plexus::network::create_udp_transport(io, lep);
        auto rend = plexus::network::create_udp_transport(io, rep);

        std::string wb = "Hello, Plexus!";
        std::string rb;

        rb.resize(wb.size());

        BOOST_REQUIRE_NO_THROW(lend->send_to(boost::asio::buffer(wb), rep, yield));

        BOOST_REQUIRE_NO_THROW(BOOST_REQUIRE_EQUAL(rb.size(), rend->receive_from(boost::asio::buffer(rb), lep, yield)));
        BOOST_REQUIRE_EQUAL(wb, rb);

        BOOST_REQUIRE_NO_THROW(rend->send_to(boost::asio::buffer(wb), lep, yield));

        BOOST_REQUIRE_NO_THROW(BOOST_REQUIRE_EQUAL(rb.size(), lend->receive_from(boost::asio::buffer(rb), rep, yield)));
        BOOST_REQUIRE_EQUAL(wb, rb);

        BOOST_REQUIRE_THROW(lend->receive_from(boost::asio::buffer(rb), rep, yield), boost::system::system_error);
    });

    io.run();
}

BOOST_AUTO_TEST_CASE(async_udp_exchange)
{
    boost::asio::io_service io;

    const boost::asio::ip::udp::endpoint lep(boost::asio::ip::address::from_string("127.0.0.1"), 1234);
    const boost::asio::ip::udp::endpoint rep(boost::asio::ip::address::from_string("127.0.0.1"), 4321);

    auto lend = plexus::network::create_udp_transport(io, lep);
    auto rend = plexus::network::create_udp_transport(io, rep);

    auto work = [](boost::asio::yield_context yield, std::shared_ptr<plexus::network::udp_socket> udp, const boost::asio::ip::udp::endpoint& peer)
    {
        std::string wb = "Hello, Plexus!";
        std::string rb;

        rb.resize(wb.size());

        BOOST_REQUIRE_NO_THROW(udp->send_to(boost::asio::buffer(wb), peer, yield));
        BOOST_REQUIRE_NO_THROW(udp->send_to(boost::asio::buffer(wb), peer, yield));
        BOOST_REQUIRE_NO_THROW(udp->send_to(boost::asio::buffer(wb), peer, yield));

        BOOST_REQUIRE_NO_THROW(BOOST_REQUIRE_EQUAL(rb.size(), udp->receive_from(boost::asio::buffer(rb), peer, yield)));
        BOOST_REQUIRE_EQUAL(wb, rb);

        BOOST_REQUIRE_NO_THROW(BOOST_REQUIRE_EQUAL(rb.size(), udp->receive_from(boost::asio::buffer(rb), peer, yield)));
        BOOST_REQUIRE_EQUAL(wb, rb);

        BOOST_REQUIRE_NO_THROW(BOOST_REQUIRE_EQUAL(rb.size(), udp->receive_from(boost::asio::buffer(rb), peer, yield)));
        BOOST_REQUIRE_EQUAL(wb, rb);
    };

    boost::asio::spawn(io, [work, lend, rep](boost::asio::yield_context yield)
    {
        work(yield, lend, rep);
    });

    boost::asio::spawn(io, [work, rend, lep](boost::asio::yield_context yield)
    {
        work(yield, rend, lep);
    });

    io.run();
}
