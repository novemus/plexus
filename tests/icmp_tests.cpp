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

const plexus::network::endpoint empty = std::make_pair("", 0);
const plexus::network::endpoint remote = std::make_pair("8.8.8.8", 0);

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
#ifdef _WIN32
    boost::test_tools::assertion_result res(false);
    res.message() << "disabled for windows";
    return res;
#else
    if (getuid() != 0)
    {
        boost::test_tools::assertion_result res(false);
        res.message() << "root privileges are required";
        return res;
    }
    return boost::test_tools::assertion_result(true);
#endif
}

}

BOOST_AUTO_TEST_CASE(icmp_ping, * boost::unit_test::precondition(is_enabled))
{
    auto icmp = plexus::network::raw::create_icmp_transport(empty);
    auto req = plexus::network::raw::icmp_packet::make_ping_packet(get_id(), 1);

    BOOST_REQUIRE_NO_THROW(icmp->send(remote, req));

    int tries = 5;
    bool success = false;
    do
    {
        try
        {
            auto env = std::make_shared<plexus::network::raw::ip_packet>(1500);
            icmp->receive(remote, env);
            auto rep = env->payload<plexus::network::raw::icmp_packet>();

            success = env->source_address().to_string() == "8.8.8.8" 
                   && env->protocol() == IPPROTO_ICMP 
                   && env->total_length() - env->header_length() == req->size() 
                   && rep->type() == plexus::network::raw::icmp_packet::echo_reply 
                   && rep->code() == 0 
                   && rep->identifier() == req->identifier() 
                   && rep->sequence_number() == req->sequence_number() 
                   && memcmp(rep->begin() + 8, req->begin() + 8, req->size() - 8) == 0;
        }
        catch (const boost::system::system_error& ex)
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
    auto icmp = plexus::network::raw::create_icmp_transport(empty);
    auto req = plexus::network::raw::icmp_packet::make_ping_packet(get_id(), 1);
    
    BOOST_REQUIRE_NO_THROW(icmp->send(remote, req, 1600, 1));

    int tries = 5;
    bool success = false;
    do
    {
        try
        {
            auto env = std::make_shared<plexus::network::raw::ip_packet>(4096);
            icmp->receive(empty, env);
            auto rep = env->payload<plexus::network::raw::icmp_packet>();

            if (env->protocol() == IPPROTO_ICMP && rep->type() == plexus::network::raw::icmp_packet::time_exceeded)
            {
                env = rep->payload<plexus::network::raw::ip_packet>();
                if (env->protocol() == IPPROTO_ICMP)
                {
                    rep = env->payload<plexus::network::raw::icmp_packet>();
                    success = env->destination_address().to_string() == "8.8.8.8"
                            && env->total_length() - env->header_length() == req->size()
                            && memcmp(rep->begin(), req->begin(), req->size()) == 0;
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
