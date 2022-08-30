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

namespace {

const plexus::network::endpoint lep = std::make_pair("127.0.0.1", 1234);
const plexus::network::endpoint rep = std::make_pair("127.0.0.1", 4321);

}

void check_udp(const plexus::network::endpoint& from, const plexus::network::endpoint& to, std::shared_ptr<plexus::network::buffer> send, std::shared_ptr<plexus::network::buffer> recv)
{
    std::shared_ptr<plexus::network::raw::ip_packet> in = std::static_pointer_cast<plexus::network::raw::ip_packet>(recv);
    std::shared_ptr<plexus::network::raw::udp_packet> out = std::dynamic_pointer_cast<plexus::network::raw::udp_packet>(send);

    BOOST_REQUIRE_EQUAL(in->protocol(), IPPROTO_UDP);
    BOOST_REQUIRE_EQUAL(out->size(), in->total_length() - in->header_length());

    auto udp = in->payload<plexus::network::raw::udp_packet>();

    if (from == to)
    {
        BOOST_REQUIRE_EQUAL(from.first, in->source_address().to_string());
        BOOST_REQUIRE_EQUAL(to.first, in->destination_address().to_string());
        BOOST_REQUIRE_EQUAL(out->source_port(), udp->dest_port());
        BOOST_REQUIRE_EQUAL(out->dest_port(), udp->source_port());
    }
    else
    {
        BOOST_REQUIRE_EQUAL(from.first, in->destination_address().to_string());
        BOOST_REQUIRE_EQUAL(to.first, in->source_address().to_string());
        BOOST_REQUIRE_EQUAL(out->dest_port(), udp->dest_port());
        BOOST_REQUIRE_EQUAL(out->source_port(), udp->source_port());
    }

    BOOST_REQUIRE_EQUAL(out->checksum(), udp->checksum());
    BOOST_REQUIRE_EQUAL(out->checksum(), udp->checksum());

    auto in_data = udp->payload<plexus::network::buffer>();
    auto out_data = out->payload<plexus::network::buffer>();

    BOOST_REQUIRE_EQUAL(std::memcmp(in_data->begin(), out_data->begin(), out_data->size()), 0);
}

BOOST_AUTO_TEST_CASE(sync_raw_udp_exchange)
{
    auto lend = plexus::network::raw::create_udp_transport(lep);
    auto rend = plexus::network::raw::create_udp_transport(rep);

    auto send = plexus::network::raw::udp_packet::make_packet(lep, rep);
    auto recv = std::make_shared<plexus::network::buffer>(1500);

    // send from left to right
    BOOST_REQUIRE_NO_THROW(lend->send(rep, send));
    BOOST_REQUIRE_NO_THROW(rend->receive(lep, recv));
    
    check_udp(lep, rep, send, recv);

    send = plexus::network::raw::udp_packet::make_packet(rep, lep);
    recv = std::make_shared<plexus::network::buffer>(1500);

    // send from right to left 
    BOOST_REQUIRE_NO_THROW(rend->send(lep, send));
    BOOST_REQUIRE_NO_THROW(lend->receive(rep, recv));

    check_udp(rep, lep, send, recv);

    BOOST_REQUIRE_THROW(rend->receive(lep, recv), boost::system::system_error);
}

BOOST_AUTO_TEST_CASE(async_raw_udp_exchange)
{
    auto lend = plexus::network::raw::create_udp_transport(lep);
    auto rend = plexus::network::raw::create_udp_transport(rep);

    auto work = [&](std::shared_ptr<plexus::network::transport> udp, const plexus::network::endpoint& s, const plexus::network::endpoint& d)
    {
        auto send = plexus::network::raw::udp_packet::make_packet(s, d);
        auto recv = std::make_shared<plexus::network::raw::ip_packet>(1500);

        BOOST_REQUIRE_NO_THROW(udp->send(d, send));
        BOOST_REQUIRE_NO_THROW(udp->send(d, send));
        BOOST_REQUIRE_NO_THROW(udp->send(d, send));

        BOOST_REQUIRE_NO_THROW(udp->receive(s, recv));
        check_udp(s, d, send, recv);

        BOOST_REQUIRE_NO_THROW(udp->receive(s, recv));
        check_udp(s, d, send, recv);

        BOOST_REQUIRE_NO_THROW(udp->receive(s, recv));
        check_udp(s, d, send, recv);
    };

    auto l = std::async(std::launch::async, work, lend, lep, rep);
    auto r = std::async(std::launch::async, work, rend, rep, lep);

    BOOST_REQUIRE_NO_THROW(l.wait());
    BOOST_REQUIRE_NO_THROW(r.wait());
}
