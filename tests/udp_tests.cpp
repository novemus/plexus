/*
 * Copyright (c) 2022 Novemus Band. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 */

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
    udp_ptr lend = plexus::network::create_udp_channel(lep);
    udp_ptr rend = plexus::network::create_udp_channel(rep);

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
    auto work = [](const endpoint_t& l, const endpoint_t& r)
    {
        udp_ptr udp = plexus::network::create_udp_channel(l);
        transfer_ptr reqv = std::make_shared<transfer_t>(r, data);
        transfer_ptr resp = std::make_shared<transfer_t>(data.size());

        BOOST_REQUIRE_EQUAL(udp->send(reqv), reqv->buffer.size());
        BOOST_REQUIRE_EQUAL(udp->send(reqv), reqv->buffer.size());
        BOOST_REQUIRE_EQUAL(udp->send(reqv), reqv->buffer.size());

        BOOST_REQUIRE_EQUAL(udp->receive(resp), reqv->buffer.size());
        BOOST_REQUIRE(resp->remote == r);
        BOOST_REQUIRE_EQUAL(std::memcmp(resp->buffer.data(), reqv->buffer.data(), reqv->buffer.size()), 0);
        BOOST_REQUIRE_EQUAL(udp->receive(resp), reqv->buffer.size());
        BOOST_REQUIRE(resp->remote == r);
        BOOST_REQUIRE_EQUAL(std::memcmp(resp->buffer.data(), reqv->buffer.data(), reqv->buffer.size()), 0);
        BOOST_REQUIRE_EQUAL(udp->receive(resp), reqv->buffer.size());
        BOOST_REQUIRE(resp->remote == r);
        BOOST_REQUIRE_EQUAL(std::memcmp(resp->buffer.data(), reqv->buffer.data(), reqv->buffer.size()), 0);
    };

    auto l = std::async(std::launch::async, work, lep, rep);
    auto r = std::async(std::launch::async, work, rep, lep);

    BOOST_REQUIRE_NO_THROW(l.wait());
    BOOST_REQUIRE_NO_THROW(r.wait());
}
