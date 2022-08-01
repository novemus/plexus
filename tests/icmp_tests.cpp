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

unsigned short get_id()
{
#if defined(BOOST_ASIO_WINDOWS)
    return static_cast<unsigned short>(::GetCurrentProcessId());
#else
    return static_cast<unsigned short>(::getpid());
#endif
}

boost::test_tools::assertion_result run_as_root(boost::unit_test::test_unit_id)
{
    boost::test_tools::assertion_result res(true);
#ifndef _WIN32
    if (getuid() != 0)
    {
        res = boost::test_tools::assertion_result(false);
        res.message() << "root privileges are required";
    }
#endif
    return res;
}

BOOST_AUTO_TEST_CASE(icmp_ping, * boost::unit_test::precondition(run_as_root))
{
    auto icmp = plexus::network::create_icmp_channel("127.0.0.1");
    auto req = plexus::network::icmp_packet::make_ping_packet(get_id(), 1);
    
    BOOST_REQUIRE_NO_THROW(icmp->send(std::make_shared<plexus::network::icmp::transfer>("127.0.0.1", req)));

    auto env = std::make_shared<plexus::network::ip_packet>(4096);
    auto tran = std::make_shared<plexus::network::icmp::transfer>(env);
    
    BOOST_REQUIRE_NO_THROW(icmp->receive(tran));

    BOOST_REQUIRE_EQUAL(tran->remote, "127.0.0.1");
    BOOST_REQUIRE_EQUAL(env->destination_address().to_string(), "127.0.0.1");
    BOOST_REQUIRE_EQUAL(env->protocol(), IPPROTO_ICMP);
    BOOST_REQUIRE_EQUAL(env->total_length() - env->header_length(), req->size());
    BOOST_CHECK_EQUAL_COLLECTIONS(req->data(), req->data() + req->size(), env->data() + env->header_length(), env->data() + env->total_length());

    BOOST_REQUIRE_NO_THROW(icmp->receive(tran));

    BOOST_REQUIRE_EQUAL(tran->remote, "127.0.0.1");
    BOOST_REQUIRE_EQUAL(env->destination_address().to_string(), "127.0.0.1");
    BOOST_REQUIRE_EQUAL(env->protocol(), IPPROTO_ICMP);
    BOOST_REQUIRE_EQUAL(env->total_length() - env->header_length(), req->size());

    auto rep = env->payload<plexus::network::icmp_packet>();
    BOOST_REQUIRE_EQUAL(rep->type(), plexus::network::icmp_packet::echo_reply);
    BOOST_REQUIRE_EQUAL(rep->code(), 0);
    BOOST_REQUIRE_EQUAL(rep->identifier(), req->identifier());
    BOOST_REQUIRE_EQUAL(rep->sequence_number(), req->sequence_number());
    BOOST_CHECK_EQUAL_COLLECTIONS(req->data() + 8, req->data() + req->size(), env->data() + env->header_length() + 8, env->data() + env->total_length());
}

BOOST_AUTO_TEST_CASE(icmp_ttl, * boost::unit_test::precondition(run_as_root))
{
    auto icmp = plexus::network::create_icmp_channel();
    auto req = plexus::network::icmp_packet::make_ping_packet(get_id(), 1);
    
    BOOST_REQUIRE_NO_THROW(icmp->send(std::make_shared<plexus::network::icmp::transfer>("8.8.8.8", req), 1600, 1));

    auto env = std::make_shared<plexus::network::ip_packet>(4096);
    auto tran = std::make_shared<plexus::network::icmp::transfer>(env);
    
    BOOST_REQUIRE_NO_THROW(icmp->receive(tran));
    BOOST_REQUIRE_EQUAL(env->protocol(), IPPROTO_ICMP);

    auto rep = env->payload<plexus::network::icmp_packet>();
    BOOST_REQUIRE_EQUAL(rep->type(), plexus::network::icmp_packet::time_exceeded);
    BOOST_REQUIRE_EQUAL(rep->code(), 0);

    env = rep->payload<plexus::network::ip_packet>();
    BOOST_REQUIRE_EQUAL(env->protocol(), IPPROTO_ICMP);
    BOOST_REQUIRE_EQUAL(env->destination_address().to_string(), "8.8.8.8");

    rep = env->payload<plexus::network::icmp_packet>();
    BOOST_CHECK_EQUAL_COLLECTIONS(req->data(), req->data() + 8, rep->data(), rep->data() + 8);
}
