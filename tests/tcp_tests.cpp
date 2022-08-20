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

void check(std::shared_ptr<plexus::network::transport::transfer> send, std::shared_ptr<plexus::network::transport::transfer> recv, bool reverse)
{
    std::shared_ptr<plexus::network::raw::ip_packet> in = std::dynamic_pointer_cast<plexus::network::raw::ip_packet>(recv->packet);
    std::shared_ptr<plexus::network::raw::tcp_packet> out = std::dynamic_pointer_cast<plexus::network::raw::tcp_packet>(send->packet);

    BOOST_REQUIRE_EQUAL(in->protocol(), IPPROTO_TCP);
    BOOST_REQUIRE_EQUAL(out->size(), in->total_length() - in->header_length());

    auto tcp = in->payload<plexus::network::raw::tcp_packet>();

    if (reverse)
    {
        BOOST_REQUIRE_EQUAL(send->remote.first, in->destination_address().to_string());
        BOOST_REQUIRE_EQUAL(out->source_port(), tcp->dest_port());
        BOOST_REQUIRE_EQUAL(out->dest_port(), tcp->source_port());
    }
    else
    {
        BOOST_REQUIRE_EQUAL(send->remote.first, in->source_address().to_string());
        BOOST_REQUIRE_EQUAL(out->dest_port(), tcp->dest_port());
        BOOST_REQUIRE_EQUAL(out->source_port(), tcp->source_port());
    }

    auto data = tcp->payload<plexus::network::buffer>();

    BOOST_REQUIRE_EQUAL(std::memcmp(out->data(), data->data(), out->size()), 0);
}

BOOST_AUTO_TEST_CASE(sync_udp_exchange)
{
    const std::initializer_list<uint8_t> payload = { 
        plexus::utils::random<uint8_t>(),
        plexus::utils::random<uint8_t>(),
        plexus::utils::random<uint8_t>(),
        plexus::utils::random<uint8_t>()
    };

    auto lend = plexus::network::create_tcp_transport(lep);
    auto rend = plexus::network::create_tcp_transport(rep);

    auto send = std::make_shared<plexus::network::transport::transfer>(rep, plexus::network::raw::tcp_packet::make_syn_packet(lep.second, rep.second, payload));
    auto recv = std::make_shared<plexus::network::transport::transfer>(std::make_shared<plexus::network::raw::ip_packet>(1500));

    // send from left to right
    BOOST_REQUIRE_NO_THROW(lend->send(send));
    BOOST_REQUIRE_NO_THROW(rend->receive(recv));

    check(send, recv, false);

    // send from right to left 
    BOOST_REQUIRE_NO_THROW(rend->send(send));
    BOOST_REQUIRE_NO_THROW(lend->receive(recv));

    check(send, recv, false);

    BOOST_REQUIRE_THROW(lend->receive(recv), boost::system::system_error);
}

BOOST_AUTO_TEST_CASE(async_udp_exchange)
{
    const std::initializer_list<uint8_t> payload = { 
        plexus::utils::random<uint8_t>(),
        plexus::utils::random<uint8_t>(),
        plexus::utils::random<uint8_t>(),
        plexus::utils::random<uint8_t>()
    };

    auto work = [&](const plexus::network::endpoint& l, const plexus::network::endpoint& r)
    {
        auto tcp = plexus::network::create_tcp_transport(l);
        auto send = std::make_shared<plexus::network::transport::transfer>(rep, plexus::network::raw::tcp_packet::make_syn_packet(lep.second, rep.second, payload));
        auto recv = std::make_shared<plexus::network::transport::transfer>(std::make_shared<plexus::network::raw::ip_packet>(1500));

        BOOST_REQUIRE_NO_THROW(tcp->send(send));
        BOOST_REQUIRE_NO_THROW(tcp->receive(recv));
        
        check(send, recv, true);

        BOOST_REQUIRE_NO_THROW(tcp->send(send));
        BOOST_REQUIRE_NO_THROW(tcp->receive(recv));
        
        check(send, recv, true);

        BOOST_REQUIRE_NO_THROW(tcp->send(send));
        BOOST_REQUIRE_NO_THROW(tcp->receive(recv));
        
        check(send, recv, true);
    };

    auto l = std::async(std::launch::async, work, lep, rep);
    auto r = std::async(std::launch::async, work, rep, lep);

    BOOST_REQUIRE_NO_THROW(l.wait());
    BOOST_REQUIRE_NO_THROW(r.wait());
}
