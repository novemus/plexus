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
#include <plexus/features.h>
#include <wormhole/wormhole.h>

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
            plexus::emailer emailer;

            in >> emailer.smtp >> emailer.imap >> emailer.login >> emailer.password >> conf.stun >> conf.hops;

            conf.app = "plexus_email_app";
            conf.qos = plexus::criteria { plexus::protocol::any, plexus::relation::either };
            conf.repo = std::filesystem::temp_directory_path().generic_u8string() + "/plexus_email_app";
            conf.mediator = emailer;

            host.owner = emailer.login;
            host.pin = "host";
            peer.owner = emailer.login;
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
            plexus::dhtnode dhtnode;

            in >> dhtnode.bootstrap >> dhtnode.port >> dhtnode.network >> conf.stun >> conf.hops;

            conf.app = "plexus_dht_app";
            conf.qos = plexus::criteria { plexus::protocol::any, plexus::relation::either };
            conf.repo = std::filesystem::temp_directory_path().generic_u8string() + "/plexus_dht_app";
            conf.mediator = dhtnode;

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

void make_advent_test(const plexus::rendezvous& receiver, const plexus::rendezvous& forwarder, const std::string& app, const std::string& repo, const plexus::identity& host, const plexus::identity& peer)
{
    auto rcv = std::async(std::launch::async, [&]()
    {
        boost::asio::io_context io;

        plexus::receive_advent(io, receiver, app, repo, host, peer, 
            [&](const plexus::identity& h, const plexus::identity& p)
            {
                BOOST_CHECK_EQUAL(host.owner, h.owner);
                BOOST_CHECK_EQUAL(host.pin, h.pin);
                BOOST_CHECK_EQUAL(peer.owner, p.owner);
                BOOST_CHECK_EQUAL(peer.pin, p.pin);
                io.stop();
            },
            [&](const plexus::identity& h, const plexus::identity& p, const std::string& error)
            {
                BOOST_CHECK_EQUAL(host.owner, h.owner);
                BOOST_CHECK_EQUAL(host.pin, h.pin);
                BOOST_CHECK_EQUAL(peer.owner, p.owner);
                BOOST_CHECK_EQUAL(peer.pin, p.pin);
                BOOST_VERIFY_MSG(false, error.c_str());
                io.stop();
            });

        io.run();
    });

    auto fwd = std::async(std::launch::async, [&]()
    {
        boost::asio::io_context io;

        plexus::forward_advent(io, forwarder, app, repo, peer, host,
            [&](const plexus::identity& h, const plexus::identity& p)
            {
                BOOST_CHECK_EQUAL(host.owner, p.owner);
                BOOST_CHECK_EQUAL(host.pin, p.pin);
                BOOST_CHECK_EQUAL(peer.owner, h.owner);
                BOOST_CHECK_EQUAL(peer.pin, h.pin);
                io.stop();
            },
            [&](const plexus::identity& h, const plexus::identity& p, const std::string& error)
            {
                BOOST_CHECK_EQUAL(host.owner, p.owner);
                BOOST_CHECK_EQUAL(host.pin, p.pin);
                BOOST_CHECK_EQUAL(peer.owner, h.owner);
                BOOST_CHECK_EQUAL(peer.pin, h.pin);
                BOOST_VERIFY_MSG(false, error.c_str());
                io.stop();
            });

        io.run();
    });

    rcv.wait();
    fwd.wait();
}

void make_rendezvous_test(const context& info)
{
    auto acc = std::async(std::launch::async, [&]()
    {
        boost::asio::io_context io;

        plexus::spawn_accept(io, info.conf, info.host, info.peer, 
            [&](const plexus::identity& host, const plexus::identity& peer, const plexus::contract& term)
            {
                BOOST_CHECK_EQUAL(info.host.owner, host.owner);
                BOOST_CHECK_EQUAL(info.host.pin, host.pin);
                BOOST_CHECK_EQUAL(info.peer.owner, peer.owner);
                BOOST_CHECK_EQUAL(info.peer.pin, peer.pin);
                BOOST_CHECK_EQUAL(term.qos.proto, plexus::protocol::udp);
                BOOST_CHECK_EQUAL(term.qos.role, plexus::relation::server);
                BOOST_CHECK_NE(term.gateway, plexus::endpoint());
                BOOST_CHECK_NE(term.mapping, plexus::endpoint());
                BOOST_CHECK_NE(term.faraway, plexus::endpoint());
                BOOST_CHECK_NE(term.secret, 0);
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
            [&](const plexus::identity& host, const plexus::identity& peer, const plexus::contract& term)
            {
                BOOST_CHECK_EQUAL(info.host.owner, peer.owner);
                BOOST_CHECK_EQUAL(info.host.pin, peer.pin);
                BOOST_CHECK_EQUAL(info.peer.owner, host.owner);
                BOOST_CHECK_EQUAL(info.peer.pin, host.pin);
                BOOST_CHECK_EQUAL(term.qos.proto, plexus::protocol::udp);
                BOOST_CHECK_EQUAL(term.qos.role, plexus::relation::client);
                BOOST_CHECK_NE(term.gateway, plexus::endpoint());
                BOOST_CHECK_NE(term.mapping, plexus::endpoint());
                BOOST_CHECK_NE(term.faraway, plexus::endpoint());
                BOOST_CHECK_NE(term.secret, 0);
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

void make_simple_contract_test(plexus::protocol proto)
{
    plexus::traverse hole {
        plexus::firewall { true, true, true, false, plexus::firewall::independent, plexus::firewall::address_and_port_dependent },
        plexus::endpoint { boost::asio::ip::make_address("192.168.0.1"), 3000 },
        plexus::endpoint { boost::asio::ip::make_address("10.0.0.2"), 3000 }
    };

    plexus::criteria qos { proto, plexus::relation::either };
    uint64_t puzzle = 1234567890;

    plexus::reference peer {
        plexus::endpoint { boost::asio::ip::make_address("10.0.0.3"), 4000 },
        plexus::firewall { true, true, true, false, plexus::firewall::independent, plexus::firewall::address_and_port_dependent },
        plexus::criteria { proto, plexus::relation::either },
        1234567890
    };

    auto info = plexus::make_contract(hole, qos, puzzle, true, peer);
    BOOST_CHECK_EQUAL(info.gateway, hole.hosting);
    BOOST_CHECK_EQUAL(info.mapping, hole.mapping);
    BOOST_CHECK_EQUAL(info.faraway, peer.mapping);
    BOOST_CHECK_EQUAL(info.secret, 0);
    BOOST_CHECK_EQUAL(info.qos.proto, proto);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::server);

    info = plexus::make_contract(hole, qos, puzzle, false, peer);
    BOOST_CHECK_EQUAL(info.qos.proto, proto);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

    qos.role = plexus::relation::server;
    peer.qos.role = plexus::relation::client;

    info = plexus::make_contract(hole, qos, puzzle, true, peer);
    BOOST_CHECK_EQUAL(info.qos.proto, proto);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::server);

    info = plexus::make_contract(hole, qos, puzzle, false, peer);
    BOOST_CHECK_EQUAL(info.qos.proto, proto);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::server);

    qos.role = plexus::relation::client;
    peer.qos.role = plexus::relation::server;

    info = plexus::make_contract(hole, qos, puzzle, true, peer);
    BOOST_CHECK_EQUAL(info.qos.proto, proto);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

    info = plexus::make_contract(hole, qos, puzzle, false, peer);
    BOOST_CHECK_EQUAL(info.qos.proto, proto);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

    peer.force.variable_address = true;
    BOOST_REQUIRE_THROW(plexus::make_contract(hole, qos, puzzle, true, peer), std::runtime_error);

    peer.force.variable_address = false;
    qos.role = plexus::relation::client;
    peer.qos.role = plexus::relation::client;

    BOOST_REQUIRE_THROW(plexus::make_contract(hole, qos, puzzle, false, peer), std::runtime_error);

    qos.role = plexus::relation::server;
    peer.qos.role = plexus::relation::server;

    BOOST_REQUIRE_THROW(plexus::make_contract(hole, qos, puzzle, true, peer), std::runtime_error);

    qos.role = plexus::relation::either;
    peer.qos.role = plexus::relation::either;
    qos.proto = proto == plexus::protocol::any ? plexus::protocol::udp : proto;
    peer.qos.proto = proto == plexus::protocol::any ? plexus::protocol::tcp : plexus::protocol(proto + 1);

    BOOST_REQUIRE_THROW(plexus::make_contract(hole, qos, puzzle, false, peer), std::runtime_error);

    qos.proto = proto;
    peer.qos.proto = proto;
    qos.role = plexus::relation::server;
    peer.qos.role = plexus::relation::either;
    hole.force.mapping = plexus::firewall::address_and_port_dependent;

    BOOST_REQUIRE_THROW(plexus::make_contract(hole, qos, puzzle, true, peer), std::runtime_error);

    qos.role = plexus::relation::either;
    peer.force.mapping = plexus::firewall::independent;
    hole.force.mapping = plexus::firewall::independent;
    peer.force.hairpin = false;
    hole.force.hairpin = false;
    hole.mapping.address = peer.mapping.address;

    BOOST_REQUIRE_THROW(plexus::make_contract(hole, qos, puzzle, false, peer), std::runtime_error);
}

void make_cone_contract_test(plexus::protocol proto)
{
    plexus::traverse hole {
        plexus::firewall { true, true, true, true, plexus::firewall::address_and_port_dependent, plexus::firewall::address_and_port_dependent },
        plexus::endpoint { boost::asio::ip::make_address("192.168.0.1"), 3000 },
        plexus::endpoint { boost::asio::ip::make_address("10.0.0.2"), 3000 }
    };

    plexus::criteria qos { proto, plexus::relation::either };
    uint64_t puzzle = 1234567890;

    plexus::reference peer {
        plexus::endpoint { boost::asio::ip::make_address("10.0.0.3"), 4000 },
        plexus::firewall { true, true, true, false, plexus::firewall::independent, plexus::firewall::independent },
        plexus::criteria { proto, plexus::relation::either },
        1234567890
    };

    auto info = plexus::make_contract(hole, qos, puzzle, true, peer);
    BOOST_CHECK_EQUAL(info.gateway, hole.hosting);
    BOOST_CHECK_EQUAL(info.mapping, hole.mapping);
    BOOST_CHECK_EQUAL(info.faraway, peer.mapping);
    BOOST_CHECK_EQUAL(info.secret, 0);
    BOOST_CHECK_EQUAL(info.qos.proto, proto);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

    info = plexus::make_contract(hole, qos, puzzle, false, peer);
    BOOST_CHECK_EQUAL(info.qos.proto, proto);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

    qos.role = plexus::relation::client;
    peer.qos.role = plexus::relation::server;

    info = plexus::make_contract(hole, qos, puzzle, true, peer);
    BOOST_CHECK_EQUAL(info.qos.proto, proto);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

    info = plexus::make_contract(hole, qos, puzzle, false, peer);
    BOOST_CHECK_EQUAL(info.qos.proto, proto);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

    qos.role = plexus::relation::either;
    peer.qos.role = plexus::relation::either;
    hole.force.variable_address = false;
    hole.force.filtering = plexus::firewall::independent;
    hole.force.mapping = plexus::firewall::independent;
    peer.force.filtering = plexus::firewall::address_and_port_dependent;
    peer.force.mapping = plexus::firewall::address_and_port_dependent;

    info = plexus::make_contract(hole, qos, puzzle, true, peer);
    BOOST_CHECK_EQUAL(info.qos.proto, proto);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::server);

    info = plexus::make_contract(hole, qos, puzzle, false, peer);
    BOOST_CHECK_EQUAL(info.qos.proto, proto);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::server);

    qos.role = plexus::relation::server;
    peer.qos.role = plexus::relation::client;

    info = plexus::make_contract(hole, qos, puzzle, true, peer);
    BOOST_CHECK_EQUAL(info.qos.proto, proto);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::server);

    info = plexus::make_contract(hole, qos, puzzle, false, peer);
    BOOST_CHECK_EQUAL(info.qos.proto, proto);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::server);

    peer.force.hairpin = false;
    hole.force.hairpin = false;
    hole.mapping.address = peer.mapping.address;

    BOOST_REQUIRE_THROW(plexus::make_contract(hole, qos, puzzle, false, peer), std::runtime_error);

    peer.force.hairpin = true;
    hole.force.hairpin = true;
    hole.mapping.address = boost::asio::ip::make_address("10.0.0.2");
    hole.force.variable_address = true;
    BOOST_REQUIRE_THROW(plexus::make_contract(hole, qos, puzzle, true, peer), std::runtime_error);

    hole.force.variable_address = false;
    hole.force.filtering = plexus::firewall::independent;
    hole.force.mapping = plexus::firewall::address_and_port_dependent;
    BOOST_REQUIRE_THROW(plexus::make_contract(hole, qos, puzzle, true, peer), std::runtime_error);

    hole.force.filtering = plexus::firewall::address_and_port_dependent;
    hole.force.mapping = plexus::firewall::independent;
    BOOST_REQUIRE_THROW(plexus::make_contract(hole, qos, puzzle, false, peer), std::runtime_error);

    hole.force.filtering = plexus::firewall::address_and_port_dependent;
    hole.force.mapping = plexus::firewall::address_and_port_dependent;
    BOOST_REQUIRE_THROW(plexus::make_contract(hole, qos, puzzle, false, peer), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(simple_udp_contract)
{
    make_simple_contract_test(plexus::protocol::udp);
}

BOOST_AUTO_TEST_CASE(simple_tcp_contract)
{
    make_simple_contract_test(plexus::protocol::tcp);
}

BOOST_AUTO_TEST_CASE(simple_ssl_contract)
{
    make_simple_contract_test(plexus::protocol::ssl);
}

BOOST_AUTO_TEST_CASE(simple_any_contract)
{
    plexus::traverse hole {
        plexus::firewall { true, true, true, false, plexus::firewall::independent, plexus::firewall::address_and_port_dependent },
        plexus::endpoint { boost::asio::ip::make_address("192.168.0.1"), 3000 },
        plexus::endpoint { boost::asio::ip::make_address("10.0.0.2"), 3000 }
    };

    plexus::criteria qos { plexus::protocol::any, plexus::relation::either };
    uint64_t puzzle = 1234567890;

    plexus::reference peer {
        plexus::endpoint { boost::asio::ip::make_address("10.0.0.3"), 4000 },
        plexus::firewall { true, true, true, false, plexus::firewall::independent, plexus::firewall::address_and_port_dependent },
        plexus::criteria { plexus::protocol::any, plexus::relation::either },
        1234567890
    };

    auto info = plexus::make_contract(hole, qos, puzzle, true, peer);
    BOOST_CHECK_EQUAL(info.gateway, hole.hosting);
    BOOST_CHECK_EQUAL(info.mapping, hole.mapping);
    BOOST_CHECK_EQUAL(info.faraway, peer.mapping);
    BOOST_CHECK_EQUAL(info.secret, 0);
    BOOST_CHECK_EQUAL(info.qos.proto, plexus::protocol::udp);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::server);

    peer.qos.proto = plexus::protocol::tcp;

    info = plexus::make_contract(hole, qos, puzzle, true, peer);
    BOOST_CHECK_EQUAL(info.qos.proto, plexus::protocol::tcp);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

    peer.qos.proto = plexus::protocol::ssl;

    info = plexus::make_contract(hole, qos, puzzle, true, peer);
    BOOST_CHECK_EQUAL(info.qos.proto, plexus::protocol::ssl);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

    peer.qos.proto = plexus::protocol::any;
    peer.force.nat = false;

    info = plexus::make_contract(hole, qos, puzzle, false, peer);
    BOOST_CHECK_EQUAL(info.qos.proto, plexus::protocol::ssl);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

    qos.proto = plexus::protocol::udp;

    info = plexus::make_contract(hole, qos, puzzle, true, peer);
    BOOST_CHECK_EQUAL(info.qos.proto, plexus::protocol::udp);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::server);

    peer.force.nat = true;
    peer.force.variable_address = true;
    qos.proto = plexus::protocol::any;
    hole.force.variable_address = true;

    BOOST_REQUIRE_THROW(plexus::make_contract(hole, qos, puzzle, true, peer), std::runtime_error);
    BOOST_REQUIRE_THROW(plexus::make_contract(hole, qos, puzzle, false, peer), std::runtime_error);

    peer.force.variable_address = false;
    hole.force.variable_address = false;
    peer.force.mapping = plexus::firewall::address_and_port_dependent;
    hole.force.mapping = plexus::firewall::address_and_port_dependent;

    BOOST_REQUIRE_THROW(plexus::make_contract(hole, qos, puzzle, true, peer), std::runtime_error);
    BOOST_REQUIRE_THROW(plexus::make_contract(hole, qos, puzzle, false, peer), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(cone_udp_contract)
{
    make_cone_contract_test(plexus::protocol::udp);
}

BOOST_AUTO_TEST_CASE(cone_tcp_contract)
{
    make_cone_contract_test(plexus::protocol::tcp);
}

BOOST_AUTO_TEST_CASE(cone_ssl_contract)
{
    make_cone_contract_test(plexus::protocol::ssl);
}

BOOST_AUTO_TEST_CASE(cone_any_contract)
{
    plexus::traverse hole {
        plexus::firewall { true, true, true, true, plexus::firewall::address_and_port_dependent, plexus::firewall::address_and_port_dependent },
        plexus::endpoint { boost::asio::ip::make_address("192.168.0.1"), 3000 },
        plexus::endpoint { boost::asio::ip::make_address("10.0.0.2"), 3000 }
    };

    plexus::criteria qos { plexus::protocol::any, plexus::relation::either };
    uint64_t puzzle = 1234567890;

    plexus::reference peer {
        plexus::endpoint { boost::asio::ip::make_address("10.0.0.3"), 4000 },
        plexus::firewall { false, true, false, false, plexus::firewall::independent, plexus::firewall::independent },
        plexus::criteria { plexus::protocol::any, plexus::relation::either },
        1234567890
    };

    auto info = plexus::make_contract(hole, qos, puzzle, true, peer);
    BOOST_CHECK_EQUAL(info.gateway, hole.hosting);
    BOOST_CHECK_EQUAL(info.mapping, hole.mapping);
    BOOST_CHECK_EQUAL(info.faraway, peer.mapping);
    BOOST_CHECK_EQUAL(info.secret, 0);
    BOOST_CHECK_EQUAL(info.qos.proto, plexus::protocol::ssl);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

    qos.proto = plexus::protocol::tcp;

    info = plexus::make_contract(hole, qos, puzzle, false, peer);
    BOOST_CHECK_EQUAL(info.qos.proto, plexus::protocol::tcp);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

    qos.proto = plexus::protocol::udp;

    info = plexus::make_contract(hole, qos, puzzle, true, peer);
    BOOST_CHECK_EQUAL(info.qos.proto, plexus::protocol::udp);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

    qos.proto = plexus::protocol::ssl;

    info = plexus::make_contract(hole, qos, puzzle, false, peer);
    BOOST_CHECK_EQUAL(info.qos.proto, plexus::protocol::ssl);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

    qos.proto = plexus::protocol::any;
    peer.force.nat = true;

    info = plexus::make_contract(hole, qos, puzzle, true, peer);
    BOOST_CHECK_EQUAL(info.qos.proto, plexus::protocol::udp);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

    qos.proto = plexus::protocol::tcp;

    BOOST_REQUIRE_THROW(plexus::make_contract(hole, qos, puzzle, true, peer), std::runtime_error);
    BOOST_REQUIRE_THROW(plexus::make_contract(hole, qos, puzzle, false, peer), std::runtime_error); 

    qos.proto = plexus::protocol::any;
    peer.force.nat = false;
    peer.force.filtering = plexus::firewall::address_and_port_dependent;

    BOOST_REQUIRE_THROW(plexus::make_contract(hole, qos, puzzle, true, peer), std::runtime_error);
    BOOST_REQUIRE_THROW(plexus::make_contract(hole, qos, puzzle, false, peer), std::runtime_error); 
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

BOOST_AUTO_TEST_CASE(plexus_email_advent, *boost::unit_test::precondition(is_emailer_context_defined))
{
    BOOST_TEST_MESSAGE("testing plexus email advent...");
    make_advent_test(with_emailer.conf.mediator, with_emailer.conf.mediator, with_emailer.conf.app, with_emailer.conf.repo, with_emailer.host, with_emailer.peer);
}

BOOST_AUTO_TEST_CASE(plexus_dht_advent, *boost::unit_test::precondition(is_dhtnode_context_defined))
{
    BOOST_TEST_MESSAGE("testing plexus dht advent...");
    make_advent_test(with_dhtnode.conf.mediator, with_dhtnode.conf.mediator, with_dhtnode.conf.app, with_dhtnode.conf.repo, with_dhtnode.host, with_dhtnode.peer);
}
