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
#include <fstream>
#include <boost/asio.hpp>
#include <boost/test/unit_test.hpp>
#include <plexus/utils.h>
#include <plexus/plexus.h>
#include <wormhole/logger.h>

namespace
{
    struct context
    {
        plexus::options  conf;
        plexus::identity host;
        plexus::identity peer;
    };

    void init_test_repo(const plexus::options& conf, const plexus::identity& host, const plexus::identity& peer)
    {
        auto host_dir = conf.repo + "/" + host.owner + "/" + host.pin;
        auto peer_dir = conf.repo + "/" + peer.owner + "/" + peer.pin;

        std::filesystem::remove_all(host_dir);
        std::filesystem::create_directories(host_dir);

        std::filesystem::create_symlink(std::filesystem::canonical("certs/server.crt"), host_dir + "/cert.crt");
        std::filesystem::create_symlink(std::filesystem::canonical("certs/server.key"), host_dir + "/private.key");
        std::filesystem::create_symlink(std::filesystem::canonical("certs/ca.crt"), host_dir + "/ca.crt");

        std::filesystem::remove_all(peer_dir);
        std::filesystem::create_directories(peer_dir);

        std::filesystem::create_symlink(std::filesystem::canonical("certs/client.crt"), peer_dir + "/cert.crt");
        std::filesystem::create_symlink(std::filesystem::canonical("certs/client.key"), peer_dir + "/private.key");
        std::filesystem::create_symlink(std::filesystem::canonical("certs/ca.crt"), peer_dir + "/ca.crt");
    }

    context with_emailer = []()
    {
        plexus::options conf;
        plexus::identity host;
        plexus::identity peer;

        auto path = plexus::utils::getenv<std::string>("PLEXUS_EMAILER_CONTEXT", "");
        if (std::filesystem::exists(path))
        {
            std::ifstream in(path);

            std::string smtp_addr, smtp_port, imap_addr, imap_port, login, password, stun_addr, stun_port, punch_hops;

            in >> smtp_addr >> smtp_port >> imap_addr >> imap_port >> login >> password >> stun_addr >> stun_port >> punch_hops;

            conf.app = "plexus_test_app";
            conf.repo = std::filesystem::temp_directory_path().generic_u8string() + "/plexus_test_app";
            conf.stun = plexus::utils::parse_endpoint<plexus::udp::endpoint>(stun_addr, stun_port);
            conf.hops = boost::lexical_cast<uint16_t>(punch_hops);
            conf.mediator = plexus::emailer {
                plexus::utils::parse_endpoint<plexus::tcp::endpoint>(smtp_addr, smtp_port),
                plexus::utils::parse_endpoint<plexus::tcp::endpoint>(imap_addr, imap_port),
                login,
                password
            };

            host.owner = login;
            host.pin = "host";
            peer.owner = login;
            peer.pin = "peer";

            init_test_repo(conf, host, peer);
        }

        return context{ conf, host, peer };
    }();

    context with_dhtnode = []()
    {
        plexus::options conf;
        plexus::identity host;
        plexus::identity peer;

        auto path = plexus::utils::getenv<std::string>("PLEXUS_DHTNODE_CONTEXT", "");
        if (std::filesystem::exists(path))
        {
            std::ifstream in(path);

            std::string bootstrap, node_port, network, stun_addr, stun_port, punch_hops;

            in >> bootstrap >> node_port >> network >> stun_addr >> stun_port >> punch_hops;

            conf.app = "plexus_test_app";
            conf.repo = std::filesystem::temp_directory_path().generic_u8string() + "/plexus_test_app";
            conf.stun = plexus::utils::parse_endpoint<plexus::udp::endpoint>(stun_addr, stun_port);
            conf.hops = boost::lexical_cast<uint16_t>(punch_hops);
            conf.mediator = plexus::dhtnode {
                bootstrap,
                boost::lexical_cast<uint16_t>(node_port),
                boost::lexical_cast<uint32_t>(network)
            };

            host.owner = "test@plexus";
            host.pin = "host";
            peer.owner = "test@plexus";
            peer.pin = "peer";

            init_test_repo(conf, host, peer);
        }

        return context{ conf, host, peer };
    }();

    boost::test_tools::assertion_result is_emailer_context_defined(boost::unit_test::test_unit_id)
    {
        return std::getenv("PLEXUS_EMAILER_CONTEXT") != nullptr;
    }

    boost::test_tools::assertion_result is_dhtnode_context_defined(boost::unit_test::test_unit_id)
    {
        return std::getenv("PLEXUS_DHTNODE_CONTEXT") != nullptr;
    }
}

void make_rendezvous_test(const context& info)
{
    auto acc = std::async(std::launch::async, [&]()
    {
        boost::asio::io_context io;

        plexus::spawn_accept(io, info.conf, info.host, info.peer, 
            [&](const plexus::identity& host, const plexus::identity& peer, const plexus::udp::endpoint& bind, const plexus::reference& gateway, const plexus::reference& faraway)
            {
                BOOST_CHECK_EQUAL(info.host.owner, host.owner);
                BOOST_CHECK_EQUAL(info.host.pin, host.pin);
                BOOST_CHECK_EQUAL(info.peer.owner, peer.owner);
                BOOST_CHECK_EQUAL(info.peer.pin, peer.pin);
                BOOST_CHECK_NE(bind.port(), 0);
                BOOST_CHECK_NE(gateway.endpoint.address().is_unspecified(), true);
                BOOST_CHECK_NE(gateway.endpoint.port(), 0);
                BOOST_CHECK_NE(gateway.puzzle, 0);
                BOOST_CHECK_NE(faraway.endpoint.address().is_unspecified(), true);
                BOOST_CHECK_NE(faraway.endpoint.port(), 0);
                BOOST_CHECK_NE(faraway.puzzle, 0);
                io.stop();
            },
            [&](const plexus::identity& host, const plexus::identity& peer, const std::string& error)
            {
                BOOST_CHECK_EQUAL(info.host.owner, host.owner);
                BOOST_CHECK_EQUAL(info.host.pin, host.pin);
                BOOST_CHECK_EQUAL(info.peer.owner, peer.owner);
                BOOST_CHECK_EQUAL(info.peer.pin, peer.pin);
                BOOST_VERIFY_MSG(false, error.c_str());
                io.stop();
            });

        io.run();
    });

    auto inv = std::async(std::launch::async, [&]()
    {
        boost::asio::io_context io;
        
        plexus::spawn_invite(io, info.conf, info.peer, info.host, 
            [&](const plexus::identity& host, const plexus::identity& peer, const plexus::udp::endpoint& bind, const plexus::reference& gateway, const plexus::reference& faraway)
            {
                BOOST_CHECK_EQUAL(info.host.owner, peer.owner);
                BOOST_CHECK_EQUAL(info.host.pin, peer.pin);
                BOOST_CHECK_EQUAL(info.peer.owner, host.owner);
                BOOST_CHECK_EQUAL(info.peer.pin, host.pin);
                BOOST_CHECK_NE(bind.port(), 0);
                BOOST_CHECK_NE(gateway.endpoint.address().is_unspecified(), true);
                BOOST_CHECK_NE(gateway.endpoint.port(), 0);
                BOOST_CHECK_NE(gateway.puzzle, 0);
                BOOST_CHECK_NE(faraway.endpoint.address().is_unspecified(), true);
                BOOST_CHECK_NE(faraway.endpoint.port(), 0);
                BOOST_CHECK_NE(faraway.puzzle, 0);
                io.stop();
            },
            [&](const plexus::identity& host, const plexus::identity& peer, const std::string& error)
            {
                BOOST_CHECK_EQUAL(info.host.owner, peer.owner);
                BOOST_CHECK_EQUAL(info.host.pin, peer.pin);
                BOOST_CHECK_EQUAL(info.peer.owner, host.owner);
                BOOST_CHECK_EQUAL(info.peer.pin, host.pin);
                BOOST_VERIFY_MSG(false, error.c_str());
                io.stop();
            });

        io.run();
    });

    acc.wait();
    inv.wait();
}

void make_streaming_test(const context& info)
{
    static const boost::system::error_code NONE_ERROR;

    std::string wb("hello plexus");
    std::string rb(wb.size(), '\0');

    auto acc = std::async(std::launch::async, [&]()
    {
        boost::asio::io_context io;

        plexus::spawn_accept(io, info.conf, info.host, info.peer,
            [&](const plexus::identity& host, const plexus::identity& peer, tubus::socket&& socket)
            {
                auto stream = std::make_shared<tubus::socket>(std::move(socket));

                BOOST_CHECK_EQUAL(info.host.owner, host.owner);
                BOOST_CHECK_EQUAL(info.host.pin, host.pin);
                BOOST_CHECK_EQUAL(info.peer.owner, peer.owner);
                BOOST_CHECK_EQUAL(info.peer.pin, peer.pin);

                boost::asio::async_read(*stream, boost::asio::buffer(rb), [&, stream](const boost::system::error_code& error, size_t size)
                {
                    BOOST_CHECK_EQUAL(error, NONE_ERROR);
                    BOOST_CHECK_EQUAL(wb, rb.substr(0, size));
                    stream->async_shutdown([&, stream](const boost::system::error_code& error)
                    {
                        BOOST_CHECK_EQUAL(error, NONE_ERROR);
                        io.stop();
                    });
                });
            },
            [&](const plexus::identity& host, const plexus::identity& peer, const std::string& error)
            {
                BOOST_CHECK_EQUAL(info.host.owner, host.owner);
                BOOST_CHECK_EQUAL(info.host.pin, host.pin);
                BOOST_CHECK_EQUAL(info.peer.owner, peer.owner);
                BOOST_CHECK_EQUAL(info.peer.pin, peer.pin);
                BOOST_VERIFY_MSG(false, error.c_str());
                io.stop();
            });

        io.run();
    });

    auto inv = std::async(std::launch::async, [&]()
    {
        boost::asio::io_context io;

        plexus::spawn_invite(io, info.conf, info.peer, info.host,
            [&](const plexus::identity& host, const plexus::identity& peer, tubus::socket&& socket)
            {
                auto stream = std::make_shared<tubus::socket>(std::move(socket));

                BOOST_CHECK_EQUAL(info.host.owner, peer.owner);
                BOOST_CHECK_EQUAL(info.host.pin, peer.pin);
                BOOST_CHECK_EQUAL(info.peer.owner, host.owner);
                BOOST_CHECK_EQUAL(info.peer.pin, host.pin);

                boost::asio::async_write(*stream, boost::asio::buffer(wb), [&, stream](const boost::system::error_code& error, size_t size) mutable
                {
                    BOOST_CHECK_EQUAL(error, NONE_ERROR);
                    BOOST_CHECK_EQUAL(wb.size(), size);
                    stream->async_shutdown([&, stream](const boost::system::error_code& error)
                    {
                        BOOST_CHECK_EQUAL(error, NONE_ERROR);
                        io.stop();
                    });
                });
            },
            [&](const plexus::identity& host, const plexus::identity& peer, const std::string& error)
            {
                BOOST_CHECK_EQUAL(info.host.owner, peer.owner);
                BOOST_CHECK_EQUAL(info.host.pin, peer.pin);
                BOOST_CHECK_EQUAL(info.peer.owner, host.owner);
                BOOST_CHECK_EQUAL(info.peer.pin, host.pin);
                BOOST_VERIFY_MSG(false, error.c_str());
                io.stop();
            });

        io.run();
    });

    acc.wait();
    inv.wait();
}

BOOST_AUTO_TEST_CASE(plexus_email_rendezvous, *boost::unit_test::precondition(is_emailer_context_defined))
{
    BOOST_TEST_MESSAGE("testing plexus email rendezvous...");
    make_rendezvous_test(with_emailer);
}

BOOST_AUTO_TEST_CASE(plexus_dht_rendezvous, *boost::unit_test::precondition(is_dhtnode_context_defined))
{
    BOOST_TEST_MESSAGE("testing plexus dht rendezvous...");
    make_rendezvous_test(with_dhtnode);
}

BOOST_AUTO_TEST_CASE(plexus_streaming_with_emailer, *boost::unit_test::precondition(is_emailer_context_defined))
{
    BOOST_TEST_MESSAGE("testing plexus streaming with email rendezvous...");
    make_streaming_test(with_emailer);
}

BOOST_AUTO_TEST_CASE(plexus_streaming_with_dhtnode, *boost::unit_test::precondition(is_dhtnode_context_defined))
{
    BOOST_TEST_MESSAGE("testing plexus streaming with dht rendezvous...");
    make_streaming_test(with_dhtnode);
}
