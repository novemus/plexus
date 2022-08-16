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


BOOST_AUTO_TEST_CASE(tcp_exchange)
{
    const std::vector<uint8_t> data = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };
    const plexus::network::endpoint lep = std::make_pair("127.0.0.1", 5678);
    const plexus::network::endpoint rep = std::make_pair("127.0.0.1", 8765);

    auto lend = plexus::network::create_tcp_channel(lep);
    auto rend = plexus::network::create_tcp_channel(rep);

    auto ltr = std::make_shared<plexus::network::tcp::transfer>(data);
    auto rtr = std::make_shared<plexus::network::tcp::transfer>(data.size());

    auto l = std::async(std::launch::async, [&]()
    {
        BOOST_REQUIRE_NO_THROW(lend->accept(rep, 2000));
        BOOST_REQUIRE_NO_THROW(BOOST_REQUIRE_EQUAL(lend->write(ltr), ltr->buffer.size()));
        BOOST_REQUIRE_NO_THROW(BOOST_REQUIRE_EQUAL(lend->read(ltr), ltr->buffer.size()));
        BOOST_REQUIRE_NO_THROW(BOOST_REQUIRE_EQUAL(std::memcmp(ltr->buffer.data(), data.data(), data.size()), 0));
        BOOST_REQUIRE_NO_THROW(lend->shutdown());
    });

    auto r = std::async(std::launch::async, [&]()
    {
        BOOST_REQUIRE_NO_THROW(rend->connect(lep, 2000));
        BOOST_REQUIRE_NO_THROW(BOOST_REQUIRE_EQUAL(rend->read(rtr), rtr->buffer.size()));
        BOOST_REQUIRE_NO_THROW(BOOST_REQUIRE_EQUAL(std::memcmp(rtr->buffer.data(), data.data(), data.size()), 0));
        BOOST_REQUIRE_NO_THROW(BOOST_REQUIRE_EQUAL(rend->write(rtr), rtr->buffer.size()));
        BOOST_REQUIRE_NO_THROW(rend->shutdown());
    });

    l.wait();
    r.wait();

    plexus::network::endpoint remote = std::make_pair("8.8.8.8", 80);

    BOOST_REQUIRE_THROW(lend->connect(remote, 2000, 3), boost::system::system_error);
    BOOST_REQUIRE_THROW(rend->connect(remote, 2000, 3), boost::system::system_error);
}
