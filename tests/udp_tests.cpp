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
#include <tubus/buffer.h>
#include <future>
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

        tubus::mutable_buffer out("plexus");
        tubus::mutable_buffer in(512);

        BOOST_REQUIRE_NO_THROW(lend->send_to(out, rep, yield));

        BOOST_REQUIRE_NO_THROW(BOOST_REQUIRE_EQUAL(out.size(), rend->receive_from(in, lep, yield)));
        BOOST_REQUIRE_EQUAL(std::memcmp(out.data(), in.data(), out.size()), 0);

        BOOST_REQUIRE_NO_THROW(rend->send_to(out, lep, yield));

        BOOST_REQUIRE_NO_THROW(BOOST_REQUIRE_EQUAL(out.size(), lend->receive_from(in, rep, yield)));
        BOOST_REQUIRE_EQUAL(std::memcmp(out.data(), in.data(), out.size()), 0);

        BOOST_REQUIRE_THROW(lend->receive_from(in, rep, yield), boost::system::system_error);
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
        tubus::mutable_buffer out("plexus");
        tubus::mutable_buffer in(512);

        BOOST_REQUIRE_NO_THROW(udp->send_to(out, peer, yield));
        BOOST_REQUIRE_NO_THROW(udp->send_to(out, peer, yield));
        BOOST_REQUIRE_NO_THROW(udp->send_to(out, peer, yield));

        BOOST_REQUIRE_NO_THROW(BOOST_REQUIRE_EQUAL(out.size(), udp->receive_from(in, peer, yield)));
        BOOST_REQUIRE_EQUAL(std::memcmp(out.data(), in.data(), out.size()), 0);

        BOOST_REQUIRE_NO_THROW(BOOST_REQUIRE_EQUAL(out.size(), udp->receive_from(in, peer, yield)));
        BOOST_REQUIRE_EQUAL(std::memcmp(out.data(), in.data(), out.size()), 0);

        BOOST_REQUIRE_NO_THROW(BOOST_REQUIRE_EQUAL(out.size(), udp->receive_from(in, peer, yield)));
        BOOST_REQUIRE_EQUAL(std::memcmp(out.data(), in.data(), out.size()), 0);
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
