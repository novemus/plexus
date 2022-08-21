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
    std::shared_ptr<plexus::network::raw::ip_packet> in = std::static_pointer_cast<plexus::network::raw::ip_packet>(recv->packet);
    std::shared_ptr<plexus::network::raw::udp_packet> out = std::dynamic_pointer_cast<plexus::network::raw::udp_packet>(send->packet);

    BOOST_REQUIRE_EQUAL(in->protocol(), IPPROTO_UDP);
    BOOST_REQUIRE_EQUAL(out->size(), in->total_length() - in->header_length());

    auto udp = in->payload<plexus::network::raw::udp_packet>();

    if (reverse)
    {
        BOOST_REQUIRE_EQUAL(send->remote.first, in->source_address().to_string());
        BOOST_REQUIRE_EQUAL(out->source_port(), udp->dest_port());
        BOOST_REQUIRE_EQUAL(out->dest_port(), udp->source_port());
    }
    else
    {
        BOOST_REQUIRE_EQUAL(send->remote.first, in->destination_address().to_string());
        BOOST_REQUIRE_EQUAL(out->dest_port(), udp->dest_port());
        BOOST_REQUIRE_EQUAL(out->source_port(), udp->source_port());
    }

    BOOST_REQUIRE_EQUAL(out->checksum(), udp->checksum());
    BOOST_REQUIRE_EQUAL(out->checksum(), udp->checksum());

    auto in_data = udp->payload<plexus::network::buffer>();
    auto out_data = out->payload<plexus::network::buffer>();

    BOOST_REQUIRE_EQUAL(std::memcmp(in_data->data(), out_data->data(), out_data->size()), 0);
}

BOOST_AUTO_TEST_CASE(sync_raw_udp_exchange)
{
    const std::initializer_list<uint8_t> payload = { 
        plexus::utils::random<uint8_t>(),
        plexus::utils::random<uint8_t>(),
        plexus::utils::random<uint8_t>(),
        plexus::utils::random<uint8_t>()
    };

    auto lend = plexus::network::create_udp_transport(lep);
    auto rend = plexus::network::create_udp_transport(rep);

    auto ls = std::make_shared<plexus::network::transport::transfer>(rep, plexus::network::raw::udp_packet::make_packet(lep.second, rep.second, payload));
    auto lr = std::make_shared<plexus::network::transport::transfer>(lep, std::make_shared<plexus::network::buffer>(1500));

    // send from left to right
    BOOST_REQUIRE_NO_THROW(lend->send(ls));
    BOOST_REQUIRE_NO_THROW(rend->receive(lr));
    
    check(ls, lr, false);

    auto rs = std::make_shared<plexus::network::transport::transfer>(lep, plexus::network::raw::udp_packet::make_packet(rep.second, lep.second, payload));
    auto rr = std::make_shared<plexus::network::transport::transfer>(rep, std::make_shared<plexus::network::buffer>(1500));

    // send from right to left 
    BOOST_REQUIRE_NO_THROW(rend->send(rs));
    BOOST_REQUIRE_NO_THROW(lend->receive(rr));

    check(rs, rr, false);

    BOOST_REQUIRE_THROW(rend->receive(lr), boost::system::system_error);
}

BOOST_AUTO_TEST_CASE(async_raw_udp_exchange)
{
    const std::initializer_list<uint8_t> payload = { 
        plexus::utils::random<uint8_t>(),
        plexus::utils::random<uint8_t>(),
        plexus::utils::random<uint8_t>(),
        plexus::utils::random<uint8_t>()
    };

    auto lend = plexus::network::create_udp_transport(lep);
    auto rend = plexus::network::create_udp_transport(rep);

    auto work = [&](std::shared_ptr<plexus::network::transport> udp, const plexus::network::endpoint& s, const plexus::network::endpoint& d)
    {
        auto send = std::make_shared<plexus::network::transport::transfer>(d, plexus::network::raw::udp_packet::make_packet(s.second, d.second, payload));
        auto recv = std::make_shared<plexus::network::transport::transfer>(d, std::make_shared<plexus::network::raw::ip_packet>(1500));

        BOOST_REQUIRE_NO_THROW(udp->send(send));
        BOOST_REQUIRE_NO_THROW(udp->send(send));
        BOOST_REQUIRE_NO_THROW(udp->send(send));

        BOOST_REQUIRE_NO_THROW(udp->receive(recv));
        check(send, recv, true);

        BOOST_REQUIRE_NO_THROW(udp->receive(recv));
        check(send, recv, true);

        BOOST_REQUIRE_NO_THROW(udp->receive(recv));
        check(send, recv, true);
    };

    auto l = std::async(std::launch::async, work, lend, lep, rep);
    auto r = std::async(std::launch::async, work, rend, rep, lep);

    BOOST_REQUIRE_NO_THROW(l.wait());
    BOOST_REQUIRE_NO_THROW(r.wait());
}
