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
#include <boost/algorithm/string.hpp>
#include <plexus/utils.h>
#include <plexus/features.h>
#include <wormhole/wormhole.h>
#include <tubus/channel.h>

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

        auto line = plexus::utils::getenv<std::string>("PLEXUS_EMAILER_CONTEXT", "");
        if (!line.empty())
        {
            std::vector<std::string> parts;
            boost::split(parts, line, boost::is_any_of(","));

            conf.app = "plexus_email_app";
            conf.repo = std::filesystem::temp_directory_path().generic_u8string() + "/plexus_email_app";
            conf.stun = plexus::endpoint::from_string(parts[0]);
            conf.hops = boost::lexical_cast<uint16_t>(parts[1]);
            conf.qos = plexus::criteria::from_string(parts[2]);
            conf.mediator = plexus::emailer {
                plexus::endpoint::from_string(parts[3]),
                plexus::endpoint::from_string(parts[4]),
                parts[5], parts[6], "", "", ""
            };

            host.owner = parts[5];
            host.pin = "host";
            peer.owner = parts[5];
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

        auto line = plexus::utils::getenv<std::string>("PLEXUS_DHTNODE_CONTEXT", "");
        if (!line.empty())
        {
            std::vector<std::string> parts;
            boost::split(parts, line, boost::is_any_of(","));

            conf.app = "plexus_dht_app";
            conf.repo = std::filesystem::temp_directory_path().generic_u8string() + "/plexus_dht_app";
            conf.stun = plexus::endpoint::from_string(parts[0]);
            conf.hops = boost::lexical_cast<uint16_t>(parts[1]);
            conf.qos = plexus::criteria::from_string(parts[2]);
            conf.mediator = plexus::dhtnode { parts[3], boost::lexical_cast<uint16_t>(parts[4]), boost::lexical_cast<uint32_t>(parts[5]) };

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
                BOOST_ERROR(error.c_str());
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
                BOOST_ERROR(error.c_str());
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
                BOOST_ERROR(error.c_str());
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
                BOOST_ERROR(error.c_str());
                io.stop();
            });

        io.run();
    });

    acc.wait();
    inv.wait();
}

void make_simple_contract_test(plexus::protocol proto)
{
    plexus::endpoint bind { boost::asio::ip::make_address("192.168.0.1"), 3000 };

    plexus::reference host;
    auto& hmap = proto == plexus::protocol::udp ? host.udp : host.tcp;
    hmap.mapping = plexus::endpoint { boost::asio::ip::make_address("10.0.0.3"), 3000 };
    hmap.force = plexus::firewall { true, true, true, false, plexus::firewall::independent, plexus::firewall::address_and_port_dependent };
    host.qos = plexus::criteria { proto, plexus::relation::either };
    host.puzzle = 1234567890;

    plexus::reference peer;
    auto& pmap = proto == plexus::protocol::udp ? peer.udp : peer.tcp;
    pmap.mapping = plexus::endpoint { boost::asio::ip::make_address("10.0.0.3"), 4000 };
    pmap.force = plexus::firewall { true, true, true, false, plexus::firewall::independent, plexus::firewall::address_and_port_dependent };
    peer.qos = plexus::criteria { proto, plexus::relation::either };
    peer.puzzle = 1234567890;

    auto info = plexus::make_contract(bind, host, peer, true);
    BOOST_CHECK_EQUAL(info.gateway, bind);
    BOOST_CHECK_EQUAL(info.mapping, hmap.mapping);
    BOOST_CHECK_EQUAL(info.faraway, pmap.mapping);
    BOOST_CHECK_EQUAL(info.secret, 0);
    BOOST_CHECK_EQUAL(info.qos.proto, proto);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::server);

    info = plexus::make_contract(bind, host, peer, false);
    BOOST_CHECK_EQUAL(info.qos.proto, proto);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

    host.qos.role = plexus::relation::server;
    peer.qos.role = plexus::relation::client;

    info = plexus::make_contract(bind, host, peer, true);
    BOOST_CHECK_EQUAL(info.qos.proto, proto);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::server);

    info = plexus::make_contract(bind, host, peer, false);
    BOOST_CHECK_EQUAL(info.qos.proto, proto);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::server);

    host.qos.role = plexus::relation::client;
    peer.qos.role = plexus::relation::server;

    info = plexus::make_contract(bind, host, peer, true);
    BOOST_CHECK_EQUAL(info.qos.proto, proto);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

    info = plexus::make_contract(bind, host, peer, false);
    BOOST_CHECK_EQUAL(info.qos.proto, proto);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

    host.qos.role = plexus::relation::client;
    peer.qos.role = plexus::relation::client;

    info = plexus::make_contract(bind, host, peer, false);
    BOOST_CHECK_EQUAL(info.qos.proto, proto);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

    pmap.force.variable_address = true;
    BOOST_REQUIRE_THROW(plexus::make_contract(bind, host, peer, true), std::runtime_error);

    pmap.force.variable_address = false;
    host.qos.role = plexus::relation::server;
    peer.qos.role = plexus::relation::server;

    BOOST_REQUIRE_THROW(plexus::make_contract(bind, host, peer, true), std::runtime_error);

    host.qos.role = plexus::relation::either;
    peer.qos.role = plexus::relation::either;
    host.qos.proto = proto == plexus::protocol::any ? plexus::protocol::udp : proto;
    peer.qos.proto = proto == plexus::protocol::any ? plexus::protocol::tcp : plexus::protocol(proto + 1);

    BOOST_REQUIRE_THROW(plexus::make_contract(bind, host, peer, false), std::runtime_error);

    host.qos.proto = proto;
    peer.qos.proto = proto;
    host.qos.role = plexus::relation::server;
    peer.qos.role = plexus::relation::either;
    hmap.force.mapping = plexus::firewall::address_and_port_dependent;

    BOOST_REQUIRE_THROW(plexus::make_contract(bind, host, peer, true), std::runtime_error);

    host.qos.role = plexus::relation::either;
    pmap.force.mapping = plexus::firewall::independent;
    pmap.force.mapping = plexus::firewall::independent;
    pmap.force.hairpin = false;
    hmap.force.hairpin = false;
    hmap.mapping.address = pmap.mapping.address;

    BOOST_REQUIRE_THROW(plexus::make_contract(bind, host, peer, false), std::runtime_error);
}

void make_cone_contract_test(plexus::protocol proto)
{
    plexus::endpoint bind { boost::asio::ip::make_address("192.168.0.1"), 3000 };

    plexus::reference host;
    auto& hmap = proto == plexus::protocol::udp ? host.udp : host.tcp;
    hmap.mapping = plexus::endpoint { boost::asio::ip::make_address("10.0.0.2"), 3000 };
    hmap.force = plexus::firewall { true, true, true, true, plexus::firewall::address_and_port_dependent, plexus::firewall::address_and_port_dependent };
    host.qos = plexus::criteria { proto, plexus::relation::either };
    host.puzzle = 1234567890;

    plexus::reference peer;
    auto& pmap = proto == plexus::protocol::udp ? peer.udp : peer.tcp;
    pmap.mapping = plexus::endpoint { boost::asio::ip::make_address("10.0.0.3"), 4000 };
    pmap.force = plexus::firewall { true, true, true, false, plexus::firewall::independent, plexus::firewall::independent };
    peer.qos = plexus::criteria { proto, plexus::relation::either };
    peer.puzzle = 1234567890;

    auto info = plexus::make_contract(bind, host, peer, true);
    BOOST_CHECK_EQUAL(info.gateway, bind);
    BOOST_CHECK_EQUAL(info.mapping, hmap.mapping);
    BOOST_CHECK_EQUAL(info.faraway, pmap.mapping);
    BOOST_CHECK_EQUAL(info.secret, 0);
    BOOST_CHECK_EQUAL(info.qos.proto, proto);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

    info = plexus::make_contract(bind, host, peer, false);
    BOOST_CHECK_EQUAL(info.qos.proto, proto);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

    host.qos.role = plexus::relation::client;
    peer.qos.role = plexus::relation::server;

    info = plexus::make_contract(bind, host, peer, true);
    BOOST_CHECK_EQUAL(info.qos.proto, proto);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

    info = plexus::make_contract(bind, host, peer, false);
    BOOST_CHECK_EQUAL(info.qos.proto, proto);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

    host.qos.role = plexus::relation::either;
    peer.qos.role = plexus::relation::either;
    hmap.force.variable_address = false;
    hmap.force.filtering = plexus::firewall::independent;
    hmap.force.mapping = plexus::firewall::independent;
    pmap.force.filtering = plexus::firewall::address_and_port_dependent;
    pmap.force.mapping = plexus::firewall::address_and_port_dependent;

    info = plexus::make_contract(bind, host, peer, true);
    BOOST_CHECK_EQUAL(info.qos.proto, proto);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::server);

    info = plexus::make_contract(bind, host, peer, false);
    BOOST_CHECK_EQUAL(info.qos.proto, proto);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::server);

    host.qos.role = plexus::relation::server;
    peer.qos.role = plexus::relation::client;

    info = plexus::make_contract(bind, host, peer, true);
    BOOST_CHECK_EQUAL(info.qos.proto, proto);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::server);

    info = plexus::make_contract(bind, host, peer, false);
    BOOST_CHECK_EQUAL(info.qos.proto, proto);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::server);

    pmap.force.hairpin = false;
    hmap.force.hairpin = false;
    hmap.mapping.address = pmap.mapping.address;

    BOOST_REQUIRE_THROW(plexus::make_contract(bind, host, peer, false), std::runtime_error);

    pmap.force.hairpin = true;
    hmap.force.hairpin = true;
    hmap.mapping.address = boost::asio::ip::make_address("10.0.0.2");
    hmap.force.variable_address = true;
    BOOST_REQUIRE_THROW(plexus::make_contract(bind, host, peer, true), std::runtime_error);

    hmap.force.variable_address = false;
    hmap.force.filtering = plexus::firewall::independent;
    hmap.force.mapping = plexus::firewall::address_and_port_dependent;
    BOOST_REQUIRE_THROW(plexus::make_contract(bind, host, peer, true), std::runtime_error);

    hmap.force.filtering = plexus::firewall::address_and_port_dependent;
    hmap.force.mapping = plexus::firewall::independent;
    BOOST_REQUIRE_THROW(plexus::make_contract(bind, host, peer, false), std::runtime_error);

    hmap.force.filtering = plexus::firewall::address_and_port_dependent;
    hmap.force.mapping = plexus::firewall::address_and_port_dependent;
    BOOST_REQUIRE_THROW(plexus::make_contract(bind, host, peer, false), std::runtime_error);
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
    plexus::endpoint bind { boost::asio::ip::make_address("192.168.0.1"), 3000 };

    plexus::reference host {
        plexus::reference::map {
            plexus::endpoint { boost::asio::ip::make_address("10.0.0.2"), 3000 },
            plexus::firewall { true, true, true, false, plexus::firewall::independent, plexus::firewall::address_and_port_dependent }
        },
        plexus::reference::map {
            plexus::endpoint { boost::asio::ip::make_address("10.0.0.2"), 4000 },
            plexus::firewall { true, true, true, false, plexus::firewall::independent, plexus::firewall::address_and_port_dependent }
        },
        plexus::criteria { plexus::protocol::any, plexus::relation::either },
        1234567890
    };

    plexus::reference peer {
        plexus::reference::map {
            plexus::endpoint { boost::asio::ip::make_address("10.0.0.3"), 4000 },
            plexus::firewall { true, true, true, false, plexus::firewall::independent, plexus::firewall::address_and_port_dependent }
        },
        plexus::reference::map {
            plexus::endpoint { boost::asio::ip::make_address("10.0.0.3"), 5000 },
            plexus::firewall { true, true, true, false, plexus::firewall::independent, plexus::firewall::address_and_port_dependent }
        },
        plexus::criteria { plexus::protocol::any, plexus::relation::either },
        1234567890
    };

    auto info = plexus::make_contract(bind, host, peer, true);
    BOOST_CHECK_EQUAL(info.gateway, bind);
    BOOST_CHECK_EQUAL(info.mapping, host.udp.mapping);
    BOOST_CHECK_EQUAL(info.faraway, peer.udp.mapping);
    BOOST_CHECK_EQUAL(info.secret, 0);
    BOOST_CHECK_EQUAL(info.qos.proto, plexus::protocol::udp);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::server);

    peer.qos.proto = plexus::protocol::tcp;

    info = plexus::make_contract(bind, host, peer, true);
    BOOST_CHECK_EQUAL(info.gateway, bind);
    BOOST_CHECK_EQUAL(info.mapping, host.tcp.mapping);
    BOOST_CHECK_EQUAL(info.faraway, peer.tcp.mapping);
    BOOST_CHECK_EQUAL(info.secret, 0);
    BOOST_CHECK_EQUAL(info.qos.proto, plexus::protocol::tcp);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

    peer.qos.proto = plexus::protocol::ssl;

    info = plexus::make_contract(bind, host, peer, true);
    BOOST_CHECK_EQUAL(info.gateway, bind);
    BOOST_CHECK_EQUAL(info.mapping, host.tcp.mapping);
    BOOST_CHECK_EQUAL(info.faraway, peer.tcp.mapping);
    BOOST_CHECK_EQUAL(info.secret, 0);
    BOOST_CHECK_EQUAL(info.qos.proto, plexus::protocol::ssl);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

    peer.qos.proto = plexus::protocol::any;
    peer.udp.force.nat = false;
    peer.tcp.force.nat = false;

    info = plexus::make_contract(bind, host, peer, false);
    BOOST_CHECK_EQUAL(info.qos.proto, plexus::protocol::ssl);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

    host.qos.proto = plexus::protocol::udp;

    info = plexus::make_contract(bind, host, peer, true);
    BOOST_CHECK_EQUAL(info.qos.proto, plexus::protocol::udp);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::server);

    peer.udp.force.nat = true;
    peer.tcp.force.nat = true;
    peer.udp.force.variable_address = true;
    peer.tcp.force.variable_address = true;
    host.udp.force.variable_address = true;
    host.tcp.force.variable_address = true;
    host.qos.proto = plexus::protocol::any;

    BOOST_REQUIRE_THROW(plexus::make_contract(bind, host, peer, true), std::runtime_error);
    BOOST_REQUIRE_THROW(plexus::make_contract(bind, host, peer, false), std::runtime_error);

    peer.udp.force.variable_address = false;
    peer.tcp.force.variable_address = false;
    host.udp.force.variable_address = false;
    host.tcp.force.variable_address = false;
    peer.udp.force.mapping = plexus::firewall::address_and_port_dependent;
    peer.tcp.force.mapping = plexus::firewall::address_and_port_dependent;
    host.udp.force.mapping = plexus::firewall::address_and_port_dependent;
    host.tcp.force.mapping = plexus::firewall::address_and_port_dependent;

    BOOST_REQUIRE_THROW(plexus::make_contract(bind, host, peer, true), std::runtime_error);
    BOOST_REQUIRE_THROW(plexus::make_contract(bind, host, peer, false), std::runtime_error);
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
    plexus::endpoint bind { boost::asio::ip::make_address("192.168.0.1"), 3000 };

    plexus::reference host {
        plexus::reference::map {
            plexus::endpoint { boost::asio::ip::make_address("10.0.0.2"), 3000 },
            plexus::firewall { true, true, true, true, plexus::firewall::address_and_port_dependent, plexus::firewall::address_and_port_dependent }
        },
        plexus::reference::map {
            plexus::endpoint { boost::asio::ip::make_address("10.0.0.2"), 4000 },
            plexus::firewall { true, true, true, true, plexus::firewall::address_and_port_dependent, plexus::firewall::address_and_port_dependent }
        },
        plexus::criteria { plexus::protocol::any, plexus::relation::either },
        1234567890
    };

    plexus::reference peer {
        plexus::reference::map {
            plexus::endpoint { boost::asio::ip::make_address("10.0.0.3"), 4000 },
            plexus::firewall { false, true, false, false, plexus::firewall::independent, plexus::firewall::independent }
        },
        plexus::reference::map {
            plexus::endpoint { boost::asio::ip::make_address("10.0.0.3"), 5000 },
            plexus::firewall { false, true, false, false, plexus::firewall::independent, plexus::firewall::independent }
        },
        plexus::criteria { plexus::protocol::any, plexus::relation::either },
        1234567890
    };

    auto info = plexus::make_contract(bind, host, peer, true);
    BOOST_CHECK_EQUAL(info.gateway, bind);
    BOOST_CHECK_EQUAL(info.mapping, host.tcp.mapping);
    BOOST_CHECK_EQUAL(info.faraway, peer.tcp.mapping);
    BOOST_CHECK_EQUAL(info.secret, 0);
    BOOST_CHECK_EQUAL(info.qos.proto, plexus::protocol::ssl);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

    host.qos.proto = plexus::protocol::tcp;

    info = plexus::make_contract(bind, host, peer, false);
    BOOST_CHECK_EQUAL(info.gateway, bind);
    BOOST_CHECK_EQUAL(info.mapping, host.tcp.mapping);
    BOOST_CHECK_EQUAL(info.faraway, peer.tcp.mapping);
    BOOST_CHECK_EQUAL(info.secret, 0);
    BOOST_CHECK_EQUAL(info.qos.proto, plexus::protocol::tcp);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

    host.qos.proto = plexus::protocol::udp;

    info = plexus::make_contract(bind, host, peer, true);
    BOOST_CHECK_EQUAL(info.gateway, bind);
    BOOST_CHECK_EQUAL(info.mapping, host.udp.mapping);
    BOOST_CHECK_EQUAL(info.faraway, peer.udp.mapping);
    BOOST_CHECK_EQUAL(info.secret, 0);
    BOOST_CHECK_EQUAL(info.qos.proto, plexus::protocol::udp);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

    host.qos.proto = plexus::protocol::ssl;

    info = plexus::make_contract(bind, host, peer, false);
    BOOST_CHECK_EQUAL(info.qos.proto, plexus::protocol::ssl);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

    host.qos.proto = plexus::protocol::any;
    peer.udp.force.nat = true;
    peer.tcp.force.nat = true;

    info = plexus::make_contract(bind, host, peer, true);
    BOOST_CHECK_EQUAL(info.qos.proto, plexus::protocol::udp);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

    host.qos.proto = plexus::protocol::tcp;

    BOOST_REQUIRE_THROW(plexus::make_contract(bind, host, peer, true), std::runtime_error);
    BOOST_REQUIRE_THROW(plexus::make_contract(bind, host, peer, false), std::runtime_error); 

    host.qos.proto = plexus::protocol::any;
    peer.udp.force.nat = false;
    peer.tcp.force.nat = false;
    peer.udp.force.filtering = plexus::firewall::address_and_port_dependent;
    peer.tcp.force.filtering = plexus::firewall::address_and_port_dependent;

    BOOST_REQUIRE_THROW(plexus::make_contract(bind, host, peer, true), std::runtime_error);
    BOOST_REQUIRE_THROW(plexus::make_contract(bind, host, peer, false), std::runtime_error); 
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

BOOST_AUTO_TEST_CASE(plexus_udp_coupling, *boost::unit_test::precondition(is_dhtnode_context_defined))
{
    wormhole::log::set(wormhole::log::debug);

    auto acc = std::async(std::launch::async, [&]()
    {
        boost::asio::io_context io;
        plexus::spawn_accept(io, with_dhtnode.conf, with_dhtnode.host, with_dhtnode.peer, 
            [&](const plexus::identity& host, const plexus::identity& peer, const plexus::contract& term)
            {
                BOOST_REQUIRE_EQUAL(term.qos.proto, plexus::protocol::udp);
                BOOST_REQUIRE_EQUAL(term.qos.role, plexus::relation::server);

                auto server = tubus::udp_channel::create(io, term.secret);
                server->open(term.gateway);
                server->accept(term.faraway, [&, server, term](const boost::system::error_code& ec)
                {
                    BOOST_REQUIRE_EQUAL(ec, boost::system::error_code());
                    BOOST_CHECK_EQUAL(server->peer(), term.faraway);
                    
                    tubus::const_buffer wb("server");
                    server->write(wb, [&, server, wb](const boost::system::error_code& ec, size_t size)
                    {
                        BOOST_REQUIRE_EQUAL(ec, boost::system::error_code());
                        BOOST_REQUIRE_EQUAL(size, wb.size());
                        
                        tubus::mutable_buffer rb(std::strlen("client"));
                        server->read(rb, [&, server, rb](const boost::system::error_code& ec, size_t size)
                        {
                            BOOST_REQUIRE_EQUAL(ec, boost::system::error_code());
                            BOOST_REQUIRE_EQUAL(size, rb.size());
                            BOOST_CHECK_EQUAL(std::memcmp(rb.data(), "client", rb.size()), 0);
                            server->close();
                            io.stop();
                        });
                    });
                });
            },
            [&](const plexus::identity& host, const plexus::identity& peer, const std::string& error)
            {
                BOOST_ERROR(error.c_str());
                io.stop();
            });

        io.run();
    });

    auto inv = std::async(std::launch::async, [&]()
    {
        boost::asio::io_context io;
        plexus::spawn_invite(io, with_dhtnode.conf, with_dhtnode.peer, with_dhtnode.host, 
            [&](const plexus::identity& host, const plexus::identity& peer, const plexus::contract& term)
            {
                BOOST_REQUIRE_EQUAL(term.qos.proto, plexus::protocol::udp);
                BOOST_REQUIRE_EQUAL(term.qos.role, plexus::relation::client);

                auto client = tubus::udp_channel::create(io, term.secret);
                client->open(term.gateway);
                client->connect(term.faraway, [&, client, term](const boost::system::error_code& ec)
                {
                    BOOST_REQUIRE_EQUAL(ec, boost::system::error_code());
                    BOOST_CHECK_EQUAL(client->peer(), term.faraway);

                    tubus::const_buffer wb("client");
                    client->write(wb, [&, client, wb](const boost::system::error_code& ec, size_t size)
                    {
                        BOOST_REQUIRE_EQUAL(ec, boost::system::error_code());
                        BOOST_REQUIRE_EQUAL(size, wb.size());

                        tubus::mutable_buffer rb(6);
                        client->read(rb, [&, client, rb](const boost::system::error_code& ec, size_t size)
                        {
                            BOOST_REQUIRE_EQUAL(ec, boost::system::error_code());
                            BOOST_REQUIRE_EQUAL(size, rb.size());
                            BOOST_CHECK_EQUAL(std::memcmp(rb.data(), "server", rb.size()), 0);
                            client->close();
                            io.stop();
                        });
                    });
                });
            },
            [&](const plexus::identity& host, const plexus::identity& peer, const std::string& error)
            {
                BOOST_ERROR(error.c_str());
                io.stop();
            });

        io.run();
    });

    acc.wait();
    inv.wait();
}

BOOST_AUTO_TEST_CASE(plexus_tcp_coupling, *boost::unit_test::precondition(is_dhtnode_context_defined))
{
    wormhole::log::set(wormhole::log::debug);

    auto acc = std::async(std::launch::async, [&]()
    {
        boost::asio::io_context io;
        plexus::spawn_accept(io, with_dhtnode.conf, with_dhtnode.host, with_dhtnode.peer, 
            [&](const plexus::identity& host, const plexus::identity& peer, const plexus::contract& term)
            {
                BOOST_REQUIRE_EQUAL(term.qos.proto, plexus::protocol::tcp);
                BOOST_REQUIRE_EQUAL(term.qos.role, plexus::relation::client);

                auto client = tubus::tcp_channel::create(io, term.secret);
                client->open(term.gateway);
                client->connect(term.faraway, [&, client, term](const boost::system::error_code& ec)
                {
                    BOOST_REQUIRE_EQUAL(ec, boost::system::error_code());
                    BOOST_CHECK_EQUAL(client->peer(), term.faraway);
                    
                    tubus::const_buffer wb("client");
                    client->write(wb, [&, client, wb](const boost::system::error_code& ec, size_t size)
                    {
                        BOOST_REQUIRE_EQUAL(ec, boost::system::error_code());
                        BOOST_REQUIRE_EQUAL(size, wb.size());
                        
                        tubus::mutable_buffer rb(std::strlen("client"));
                        client->read(rb, [&, client, rb](const boost::system::error_code& ec, size_t size)
                        {
                            BOOST_REQUIRE_EQUAL(ec, boost::system::error_code());
                            BOOST_REQUIRE_EQUAL(size, rb.size());
                            BOOST_CHECK_EQUAL(std::memcmp(rb.data(), "client", rb.size()), 0);
                            client->close();
                            io.stop();
                        });
                    });
                });
            },
            [&](const plexus::identity& host, const plexus::identity& peer, const std::string& error)
            {
                BOOST_ERROR(error.c_str());
                io.stop();
            });

        io.run();
    });

    auto inv = std::async(std::launch::async, [&]()
    {
        boost::asio::io_context io;
        plexus::spawn_invite(io, with_dhtnode.conf, with_dhtnode.peer, with_dhtnode.host, 
            [&](const plexus::identity& host, const plexus::identity& peer, const plexus::contract& term)
            {
                BOOST_REQUIRE_EQUAL(term.qos.proto, plexus::protocol::tcp);
                BOOST_REQUIRE_EQUAL(term.qos.role, plexus::relation::client);

                auto client = tubus::tcp_channel::create(io, term.secret);
                client->open(term.gateway);
                client->connect(term.faraway, [&, client, term](const boost::system::error_code& ec)
                {
                    BOOST_REQUIRE_EQUAL(ec, boost::system::error_code());
                    BOOST_CHECK_EQUAL(client->peer(), term.faraway);

                    tubus::const_buffer wb("client");
                    client->write(wb, [&, client, wb](const boost::system::error_code& ec, size_t size)
                    {
                        BOOST_REQUIRE_EQUAL(ec, boost::system::error_code());
                        BOOST_REQUIRE_EQUAL(size, wb.size());

                        tubus::mutable_buffer rb(6);
                        client->read(rb, [&, client, rb](const boost::system::error_code& ec, size_t size)
                        {
                            BOOST_REQUIRE_EQUAL(ec, boost::system::error_code());
                            BOOST_REQUIRE_EQUAL(size, rb.size());
                            BOOST_CHECK_EQUAL(std::memcmp(rb.data(), "client", rb.size()), 0);
                            client->close();
                            io.stop();
                        });
                    });
                });
            },
            [&](const plexus::identity& host, const plexus::identity& peer, const std::string& error)
            {
                BOOST_ERROR(error.c_str());
                io.stop();
            });

        io.run();
    });

    acc.wait();
    inv.wait();
}

BOOST_AUTO_TEST_CASE(plexus_stun_test, *boost::unit_test::precondition(is_dhtnode_context_defined))
{
    boost::asio::io_context io;
    plexus::explore_network(io, with_dhtnode.conf.bind, with_dhtnode.conf.stun,
        [&](const plexus::traverse& pass)
        {
            BOOST_TEST_MESSAGE("stun test is ok");
        },
        [&](const std::string& error)
        {
            BOOST_ERROR(error.c_str());
            io.stop();
        });

    io.run();
}
