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

boost::test_tools::assertion_result is_enabled(boost::unit_test::test_unit_id)
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

namespace {

const plexus::network::endpoint local = std::make_pair("", 0);
const plexus::network::endpoint remote = std::make_pair("8.8.8.8", 0);

}

BOOST_AUTO_TEST_CASE(icmp_ping, * boost::unit_test::precondition(is_enabled))
{
    auto icmp = plexus::network::create_icmp_transport(local);
    auto req = plexus::network::raw::icmp_packet::make_ping_packet(get_id(), 1);
    
    BOOST_REQUIRE_NO_THROW(icmp->send(std::make_shared<plexus::network::transport::transfer>(remote, req)));

    int tries = 5;
    bool success = false;
    do
    {
        try
        {
            auto env = std::make_shared<plexus::network::raw::ip_packet>(1500);
            
            icmp->receive(std::make_shared<plexus::network::transport::transfer>(env));
            
            auto rep = env->payload<plexus::network::raw::icmp_packet>();

            BOOST_TEST_MESSAGE(plexus::utils::format("received icmp: %s", plexus::utils::to_hexadecimal(rep->data(), env->total_length() - env->header_length()).c_str()));

            success = env->source_address().to_string() == "8.8.8.8"
                    && env->protocol() == IPPROTO_ICMP
                    && env->total_length() - env->header_length() == req->size()
                    && rep->type() == plexus::network::raw::icmp_packet::echo_reply
                    && rep->code() == 0
                    && rep->identifier() == req->identifier()
                    && rep->sequence_number() == req->sequence_number()
                    && memcmp(rep->data() + 8, req->data() + 8, req->size() - 8) == 0;
        }
        catch(const boost::system::system_error& ex) 
        {
            BOOST_REQUIRE_EQUAL(ex.code(), boost::asio::error::operation_aborted);
            break;
        }
    } 
    while (tries > 0 && !success);

    BOOST_CHECK_MESSAGE(success, "no ping reply packet");
}

BOOST_AUTO_TEST_CASE(icmp_ttl, * boost::unit_test::precondition(is_enabled))
{
    auto icmp = plexus::network::create_icmp_transport(local);
    auto req = plexus::network::raw::icmp_packet::make_ping_packet(get_id(), 1);
    
    BOOST_REQUIRE_NO_THROW(icmp->send(std::make_shared<plexus::network::transport::transfer>(remote, req), 1600, 1));

    int tries = 5;
    bool success = false;
    do
    {
        try
        {
            auto env = std::make_shared<plexus::network::raw::ip_packet>(4096);
            
            icmp->receive(std::make_shared<plexus::network::transport::transfer>(env));
            
            auto rep = env->payload<plexus::network::raw::icmp_packet>();
            
            BOOST_TEST_MESSAGE(plexus::utils::format("received icmp: %s", plexus::utils::to_hexadecimal(rep->data(), env->total_length() - env->header_length()).c_str()));

            if (env->protocol() == IPPROTO_ICMP && rep->type() == plexus::network::raw::icmp_packet::time_exceeded)
            {
                env = rep->payload<plexus::network::raw::ip_packet>();
                if (env->protocol() == IPPROTO_ICMP)
                {
                    rep = env->payload<plexus::network::raw::icmp_packet>();
                    success = env->destination_address().to_string() == "8.8.8.8"
                            && env->total_length() - env->header_length() == req->size()
                            && memcmp(rep->data(), req->data(), req->size()) == 0;
                }
            }
        }
        catch(const boost::system::system_error& ex) 
        {
            BOOST_REQUIRE_EQUAL(ex.code(), boost::asio::error::operation_aborted);
            break;
        }
    } 
    while (tries > 0 && !success);

    BOOST_CHECK_MESSAGE(success, "no time exceeded packet");
}
