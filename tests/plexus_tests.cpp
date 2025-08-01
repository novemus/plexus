/*
 * Copyright (c) 2022 Novemus Band. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 */

#include <filesystem>
#include <boost/asio.hpp>
#include <boost/test/unit_test.hpp>
#include <plexus/utils.h>
#include <plexus/plexus.h>

namespace
{
    plexus::options  g_conf;
    plexus::identity g_host;
    plexus::identity g_peer;

    boost::test_tools::assertion_result is_enabled(boost::unit_test::test_unit_id)
    {
        static std::once_flag flag;
        std::call_once(flag, []()
        {
            // only enable these tests if the NAT supports 'hairpinning'
            auto args = plexus::utils::getenv<std::string>("PLEXUS_MODULE_TEST_ARGS", "");

            std::smatch match;
            if (std::regex_match(args, match, std::regex("^emailer#(.+):(.+),(.+):(.+),(.+),(.+),(.+):(.+),(.+)$")))
            {
                plexus::emailer mediator {
                    plexus::utils::parse_endpoint<plexus::tcp::endpoint>(match[1].str(), match[2].str()),
                    plexus::utils::parse_endpoint<plexus::tcp::endpoint>(match[3].str(), match[4].str()),
                    match[5].str(),
                    match[6].str() 
                };

                g_conf.app = "plexus_test_app";
                g_conf.repo = std::filesystem::temp_directory_path().generic_u8string() + "/plexus_test_app";
                g_conf.stun = plexus::utils::parse_endpoint<plexus::udp::endpoint>(match[7].str(), match[8].str());
                g_conf.hops = boost::lexical_cast<uint16_t>(match[9].str());
                g_conf.mediator = mediator;
                
                g_host.owner = mediator.login;
                g_host.pin = "host";
                g_peer.owner = mediator.login;
                g_peer.pin = "peer";
            }
            else if (std::regex_match(args, match, std::regex("^dhtnode#(.+),(.+),(.+),(.+):(.+),(.+)$")))
            {
                plexus::dhtnode mediator {
                    match[1].str(),
                    boost::lexical_cast<uint16_t>(match[2].str()),
                    boost::lexical_cast<uint32_t>(match[3].str())
                };

                g_conf.app = "plexus_test_app";
                g_conf.repo = std::filesystem::temp_directory_path().generic_u8string() + "/plexus_test_app";
                g_conf.stun = plexus::utils::parse_endpoint<plexus::udp::endpoint>(match[4].str(), match[5].str());
                g_conf.hops = boost::lexical_cast<uint16_t>(match[6].str());
                g_conf.mediator = mediator;

                g_host.owner = "host@plexus";
                g_host.pin = "host";
                g_peer.owner = "peer@plexus";
                g_peer.pin = "peer";
            }

            if (!g_conf.app.empty())
            {
                auto host_dir = g_conf.repo + "/" + g_host.owner + "/" + g_host.pin;
                auto peer_dir = g_conf.repo + "/" + g_peer.owner + "/" + g_peer.pin;

                if (!std::filesystem::exists(host_dir))
                {
                    std::filesystem::create_directories(host_dir);
                    std::filesystem::create_symlink(std::filesystem::canonical("certs/server.crt"), host_dir + "/cert.crt");
                    std::filesystem::create_symlink(std::filesystem::canonical("certs/server.key"), host_dir + "/private.key");
                    std::filesystem::create_symlink(std::filesystem::canonical("certs/ca.crt"), host_dir + "/ca.crt");
                }

                if (!std::filesystem::exists(peer_dir))
                {
                    std::filesystem::create_directories(peer_dir);
                    std::filesystem::create_symlink(std::filesystem::canonical("certs/client.crt"), peer_dir + "/cert.crt");
                    std::filesystem::create_symlink(std::filesystem::canonical("certs/client.key"), peer_dir + "/private.key");
                    std::filesystem::create_symlink(std::filesystem::canonical("certs/ca.crt"), peer_dir + "/ca.crt");
                }
            }
        });

        return !g_conf.app.empty();
    }
}

BOOST_AUTO_TEST_CASE(plexus_meeting, *boost::unit_test::precondition(is_enabled))
{
    boost::asio::io_context io;

    std::atomic<bool> host_done = false;
    std::atomic<bool> peer_done = false;
    std::atomic<bool> host_fail = false;
    std::atomic<bool> peer_fail = false;

    plexus::spawn_accept(io, g_conf, g_host, g_peer, 
        [&](const plexus::identity& host, const plexus::identity& peer, const plexus::udp::endpoint& bind, const plexus::reference& gateway, const plexus::reference& faraway)
        {
            BOOST_CHECK_EQUAL(g_host.owner, host.owner);
            BOOST_CHECK_EQUAL(g_host.pin, host.pin);
            BOOST_CHECK_EQUAL(g_peer.owner, peer.owner);
            BOOST_CHECK_EQUAL(g_peer.pin, peer.pin);
            BOOST_CHECK_NE(bind.port(), 0);
            BOOST_CHECK_NE(gateway.endpoint.address().is_unspecified(), true);
            BOOST_CHECK_NE(gateway.endpoint.port(), 0);
            BOOST_CHECK_NE(gateway.puzzle, 0);
            BOOST_CHECK_NE(faraway.endpoint.address().is_unspecified(), true);
            BOOST_CHECK_NE(faraway.endpoint.port(), 0);
            BOOST_CHECK_NE(faraway.puzzle, 0);
            host_done = true;
        },
        [&](const plexus::identity& host, const plexus::identity& peer, const std::string& error)
        {
            BOOST_CHECK_EQUAL(g_host.owner, host.owner);
            BOOST_CHECK_EQUAL(g_host.pin, host.pin);
            BOOST_CHECK_EQUAL(g_peer.owner, peer.owner);
            BOOST_CHECK_EQUAL(g_peer.pin, peer.pin);
            BOOST_VERIFY_MSG(false, error.c_str());
            host_fail = true;
        });

    plexus::spawn_invite(io, g_conf, g_peer, g_host, 
        [&](const plexus::identity& host, const plexus::identity& peer, const plexus::udp::endpoint& bind, const plexus::reference& gateway, const plexus::reference& faraway)
        {
            BOOST_CHECK_EQUAL(g_host.owner, peer.owner);
            BOOST_CHECK_EQUAL(g_host.pin, peer.pin);
            BOOST_CHECK_EQUAL(g_peer.owner, host.owner);
            BOOST_CHECK_EQUAL(g_peer.pin, host.pin);
            BOOST_CHECK_NE(bind.port(), 0);
            BOOST_CHECK_NE(gateway.endpoint.address().is_unspecified(), true);
            BOOST_CHECK_NE(gateway.endpoint.port(), 0);
            BOOST_CHECK_NE(gateway.puzzle, 0);
            BOOST_CHECK_NE(faraway.endpoint.address().is_unspecified(), true);
            BOOST_CHECK_NE(faraway.endpoint.port(), 0);
            BOOST_CHECK_NE(faraway.puzzle, 0);
            peer_done = true;
        },
        [&](const plexus::identity& host, const plexus::identity& peer, const std::string& error)
        {
            BOOST_CHECK_EQUAL(g_host.owner, peer.owner);
            BOOST_CHECK_EQUAL(g_host.pin, peer.pin);
            BOOST_CHECK_EQUAL(g_peer.owner, host.owner);
            BOOST_CHECK_EQUAL(g_peer.pin, host.pin);
            BOOST_VERIFY_MSG(false, error.c_str());
            peer_fail = true;
        });

    while (!host_done || !peer_done)
    {
        if (peer_fail || host_fail)
        {
            io.stop();
            break;
        }
        io.run_one();
    }
}

BOOST_AUTO_TEST_CASE(plexus_streaming, *boost::unit_test::precondition(is_enabled))
{
    boost::asio::io_context io;

    static const boost::system::error_code NONE_ERROR;

    std::atomic<bool> host_done = false;
    std::atomic<bool> peer_done = false;
    std::atomic<bool> host_fail = false;
    std::atomic<bool> peer_fail = false;

    std::string wb("hello plexus");
    std::string rb(wb.size(), '\0');

    plexus::spawn_accept(io, g_conf, g_host, g_peer, 
        [&](const plexus::identity& host, const plexus::identity& peer, tubus::socket&& socket)
        {
            auto stream = std::make_shared<tubus::socket>(std::move(socket));

            BOOST_CHECK_EQUAL(g_host.owner, host.owner);
            BOOST_CHECK_EQUAL(g_host.pin, host.pin);
            BOOST_CHECK_EQUAL(g_peer.owner, peer.owner);
            BOOST_CHECK_EQUAL(g_peer.pin, peer.pin);

            boost::asio::async_read(*stream, boost::asio::buffer(rb), [&, stream](const boost::system::error_code& error, size_t size)
            {
                BOOST_CHECK_EQUAL(error, NONE_ERROR);
                BOOST_CHECK_EQUAL(wb, rb.substr(0, size));
                stream->async_shutdown([&, stream](const boost::system::error_code& error)
                {
                    BOOST_CHECK_EQUAL(error, NONE_ERROR);
                    host_done = true;
                });
            });
        },
        [&](const plexus::identity& host, const plexus::identity& peer, const std::string& error)
        {
            BOOST_CHECK_EQUAL(g_host.owner, host.owner);
            BOOST_CHECK_EQUAL(g_host.pin, host.pin);
            BOOST_CHECK_EQUAL(g_peer.owner, peer.owner);
            BOOST_CHECK_EQUAL(g_peer.pin, peer.pin);
            BOOST_VERIFY_MSG(false, error.c_str());
            host_fail = true;
        });

    plexus::spawn_invite(io, g_conf, g_peer, g_host, 
        [&](const plexus::identity& host, const plexus::identity& peer, tubus::socket&& socket)
        {
            auto stream = std::make_shared<tubus::socket>(std::move(socket));

            BOOST_CHECK_EQUAL(g_host.owner, peer.owner);
            BOOST_CHECK_EQUAL(g_host.pin, peer.pin);
            BOOST_CHECK_EQUAL(g_peer.owner, host.owner);
            BOOST_CHECK_EQUAL(g_peer.pin, host.pin);

            boost::asio::async_write(*stream, boost::asio::buffer(wb), [&, stream](const boost::system::error_code& error, size_t size) mutable
            {
                BOOST_CHECK_EQUAL(error, NONE_ERROR);
                BOOST_CHECK_EQUAL(wb.size(), size);
                stream->async_shutdown([&, stream](const boost::system::error_code& error)
                {
                    BOOST_CHECK_EQUAL(error, NONE_ERROR);
                    peer_done = true;
                });
            });
        },
        [&](const plexus::identity& host, const plexus::identity& peer, const std::string& error)
        {
            BOOST_CHECK_EQUAL(g_host.owner, peer.owner);
            BOOST_CHECK_EQUAL(g_host.pin, peer.pin);
            BOOST_CHECK_EQUAL(g_peer.owner, host.owner);
            BOOST_CHECK_EQUAL(g_peer.pin, host.pin);
            BOOST_VERIFY_MSG(false, error.c_str());
            peer_fail = true;
        });

    while (!host_done || !peer_done)
    {
        if (peer_fail || host_fail)
        {
            io.stop();
            break;
        }
        io.run_one();
    }
}
