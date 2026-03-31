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

namespace tests
{
    void make_base_contract_test(plexus::protocol proto)
    {
        plexus::endpoint bind { boost::asio::ip::make_address("192.168.0.1"), 3000 };

        plexus::reference host;
        auto& hmap = proto == plexus::protocol::udp ? host.udp : host.tcp;
        hmap.outer = plexus::endpoint { boost::asio::ip::make_address("10.0.0.3"), 3000 };
        hmap.force = plexus::firewall { true, true, true, false, plexus::firewall::independent, plexus::firewall::address_and_port_dependent };
        host.qos = plexus::criteria { proto, plexus::relation::either };
        host.puzzle = 1234567890;

        plexus::reference peer;
        auto& pmap = proto == plexus::protocol::udp ? peer.udp : peer.tcp;
        pmap.outer = plexus::endpoint { boost::asio::ip::make_address("10.0.0.3"), 4000 };
        pmap.force = plexus::firewall { true, true, true, false, plexus::firewall::independent, plexus::firewall::address_and_port_dependent };
        peer.qos = plexus::criteria { proto, plexus::relation::either };
        peer.puzzle = 1234567890;

        auto info = plexus::make_contract(bind, bind, host, peer, true);
        BOOST_CHECK_EQUAL(info.inner, bind);
        BOOST_CHECK_EQUAL(info.outer, hmap.outer);
        BOOST_CHECK_EQUAL(info.alien, pmap.outer);
        BOOST_CHECK_EQUAL(info.secret, 0);
        BOOST_CHECK_EQUAL(info.qos.proto, proto);
        BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::server);

        info = plexus::make_contract(bind, bind, host, peer, false);
        BOOST_CHECK_EQUAL(info.qos.proto, proto);
        BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

        host.qos.role = plexus::relation::server;
        peer.qos.role = plexus::relation::client;

        info = plexus::make_contract(bind, bind, host, peer, true);
        BOOST_CHECK_EQUAL(info.qos.proto, proto);
        BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::server);

        info = plexus::make_contract(bind, bind, host, peer, false);
        BOOST_CHECK_EQUAL(info.qos.proto, proto);
        BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::server);

        host.qos.role = plexus::relation::client;
        peer.qos.role = plexus::relation::server;

        info = plexus::make_contract(bind, bind, host, peer, true);
        BOOST_CHECK_EQUAL(info.qos.proto, proto);
        BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

        info = plexus::make_contract(bind, bind, host, peer, false);
        BOOST_CHECK_EQUAL(info.qos.proto, proto);
        BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

        host.qos.role = plexus::relation::client;
        peer.qos.role = plexus::relation::client;

        info = plexus::make_contract(bind, bind, host, peer, false);
        BOOST_CHECK_EQUAL(info.qos.proto, proto);
        BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

        pmap.force.variable_address = true;
        BOOST_REQUIRE_THROW(plexus::make_contract(bind, bind, host, peer, true), std::runtime_error);

        pmap.force.variable_address = false;
        host.qos.role = plexus::relation::server;
        peer.qos.role = plexus::relation::server;

        BOOST_REQUIRE_THROW(plexus::make_contract(bind, bind, host, peer, true), std::runtime_error);

        host.qos.role = plexus::relation::either;
        peer.qos.role = plexus::relation::either;
        host.qos.proto = proto == plexus::protocol::any ? plexus::protocol::udp : proto;
        peer.qos.proto = proto == plexus::protocol::any ? plexus::protocol::tcp : plexus::protocol(proto + 1);

        BOOST_REQUIRE_THROW(plexus::make_contract(bind, bind, host, peer, false), std::runtime_error);

        host.qos.proto = proto;
        peer.qos.proto = proto;
        host.qos.role = plexus::relation::server;
        peer.qos.role = plexus::relation::either;
        hmap.force.mapping = plexus::firewall::address_and_port_dependent;

        BOOST_REQUIRE_THROW(plexus::make_contract(bind, bind, host, peer, true), std::runtime_error);

        host.qos.role = plexus::relation::either;
        pmap.force.mapping = plexus::firewall::independent;
        pmap.force.mapping = plexus::firewall::independent;
        pmap.force.hairpin = false;
        hmap.force.hairpin = false;
        hmap.outer.address = pmap.outer.address;

        BOOST_REQUIRE_THROW(plexus::make_contract(bind, bind, host, peer, false), std::runtime_error);
    }

    void make_cone_contract_test(plexus::protocol proto)
    {
        plexus::endpoint bind { boost::asio::ip::make_address("192.168.0.1"), 3000 };

        plexus::reference host;
        auto& hmap = proto == plexus::protocol::udp ? host.udp : host.tcp;
        hmap.outer = plexus::endpoint { boost::asio::ip::make_address("10.0.0.2"), 3000 };
        hmap.force = plexus::firewall { true, true, true, true, plexus::firewall::address_and_port_dependent, plexus::firewall::address_and_port_dependent };
        host.qos = plexus::criteria { proto, plexus::relation::either };
        host.puzzle = 1234567890;

        plexus::reference peer;
        auto& pmap = proto == plexus::protocol::udp ? peer.udp : peer.tcp;
        pmap.outer = plexus::endpoint { boost::asio::ip::make_address("10.0.0.3"), 4000 };
        pmap.force = plexus::firewall { true, true, true, false, plexus::firewall::independent, plexus::firewall::independent };
        peer.qos = plexus::criteria { proto, plexus::relation::either };
        peer.puzzle = 1234567890;

        auto info = plexus::make_contract(bind, bind, host, peer, true);
        BOOST_CHECK_EQUAL(info.inner, bind);
        BOOST_CHECK_EQUAL(info.outer, hmap.outer);
        BOOST_CHECK_EQUAL(info.alien, pmap.outer);
        BOOST_CHECK_EQUAL(info.secret, 0);
        BOOST_CHECK_EQUAL(info.qos.proto, proto);
        BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

        info = plexus::make_contract(bind, bind, host, peer, false);
        BOOST_CHECK_EQUAL(info.qos.proto, proto);
        BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

        host.qos.role = plexus::relation::client;
        peer.qos.role = plexus::relation::server;

        info = plexus::make_contract(bind, bind, host, peer, true);
        BOOST_CHECK_EQUAL(info.qos.proto, proto);
        BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

        info = plexus::make_contract(bind, bind, host, peer, false);
        BOOST_CHECK_EQUAL(info.qos.proto, proto);
        BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

        host.qos.role = plexus::relation::either;
        peer.qos.role = plexus::relation::either;
        hmap.force.variable_address = false;
        hmap.force.filtering = plexus::firewall::independent;
        hmap.force.mapping = plexus::firewall::independent;
        pmap.force.filtering = plexus::firewall::address_and_port_dependent;
        pmap.force.mapping = plexus::firewall::address_and_port_dependent;

        info = plexus::make_contract(bind, bind, host, peer, true);
        BOOST_CHECK_EQUAL(info.qos.proto, proto);
        BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::server);

        info = plexus::make_contract(bind, bind, host, peer, false);
        BOOST_CHECK_EQUAL(info.qos.proto, proto);
        BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::server);

        host.qos.role = plexus::relation::server;
        peer.qos.role = plexus::relation::client;

        info = plexus::make_contract(bind, bind, host, peer, true);
        BOOST_CHECK_EQUAL(info.qos.proto, proto);
        BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::server);

        info = plexus::make_contract(bind, bind, host, peer, false);
        BOOST_CHECK_EQUAL(info.qos.proto, proto);
        BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::server);

        pmap.force.hairpin = false;
        hmap.force.hairpin = false;
        hmap.outer.address = pmap.outer.address;

        BOOST_REQUIRE_THROW(plexus::make_contract(bind, bind, host, peer, false), std::runtime_error);

        pmap.force.hairpin = true;
        hmap.force.hairpin = true;
        hmap.outer.address = boost::asio::ip::make_address("10.0.0.2");
        hmap.force.variable_address = true;
        BOOST_REQUIRE_THROW(plexus::make_contract(bind, bind, host, peer, true), std::runtime_error);

        hmap.force.variable_address = false;
        hmap.force.filtering = plexus::firewall::independent;
        hmap.force.mapping = plexus::firewall::address_and_port_dependent;
        BOOST_REQUIRE_THROW(plexus::make_contract(bind, bind, host, peer, true), std::runtime_error);

        hmap.force.filtering = plexus::firewall::address_and_port_dependent;
        hmap.force.mapping = plexus::firewall::independent;
        BOOST_REQUIRE_THROW(plexus::make_contract(bind, bind, host, peer, false), std::runtime_error);

        hmap.force.filtering = plexus::firewall::address_and_port_dependent;
        hmap.force.mapping = plexus::firewall::address_and_port_dependent;
        BOOST_REQUIRE_THROW(plexus::make_contract(bind, bind, host, peer, false), std::runtime_error);
    }
}

BOOST_AUTO_TEST_CASE(simple_udp_contract)
{
    tests::make_base_contract_test(plexus::protocol::udp);
}

BOOST_AUTO_TEST_CASE(simple_tcp_contract)
{
    tests::make_base_contract_test(plexus::protocol::tcp);
}

BOOST_AUTO_TEST_CASE(simple_ssl_contract)
{
    tests::make_base_contract_test(plexus::protocol::ssl);
}

BOOST_AUTO_TEST_CASE(simple_any_contract)
{
    plexus::endpoint udp { boost::asio::ip::make_address("192.168.0.1"), 3000 };
    plexus::endpoint tcp { boost::asio::ip::make_address("192.168.0.1"), 4000 };

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

    auto info = plexus::make_contract(udp, tcp, host, peer, true);
    BOOST_CHECK_EQUAL(info.inner, udp);
    BOOST_CHECK_EQUAL(info.outer, host.udp.outer);
    BOOST_CHECK_EQUAL(info.alien, peer.udp.outer);
    BOOST_CHECK_EQUAL(info.secret, 0);
    BOOST_CHECK_EQUAL(info.qos.proto, plexus::protocol::udp);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::server);

    peer.qos.proto = plexus::protocol::tcp;

    info = plexus::make_contract(udp, tcp, host, peer, true);
    BOOST_CHECK_EQUAL(info.inner, tcp);
    BOOST_CHECK_EQUAL(info.outer, host.tcp.outer);
    BOOST_CHECK_EQUAL(info.alien, peer.tcp.outer);
    BOOST_CHECK_EQUAL(info.secret, 0);
    BOOST_CHECK_EQUAL(info.qos.proto, plexus::protocol::tcp);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

    peer.qos.proto = plexus::protocol::ssl;

    info = plexus::make_contract(udp, tcp, host, peer, true);
    BOOST_CHECK_EQUAL(info.inner, tcp);
    BOOST_CHECK_EQUAL(info.outer, host.tcp.outer);
    BOOST_CHECK_EQUAL(info.alien, peer.tcp.outer);
    BOOST_CHECK_EQUAL(info.secret, 0);
    BOOST_CHECK_EQUAL(info.qos.proto, plexus::protocol::ssl);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

    peer.qos.proto = plexus::protocol::any;
    peer.udp.force.nat = false;
    peer.tcp.force.nat = false;

    info = plexus::make_contract(udp, tcp, host, peer, false);
    BOOST_CHECK_EQUAL(info.qos.proto, plexus::protocol::ssl);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

    host.qos.proto = plexus::protocol::udp;

    info = plexus::make_contract(udp, tcp, host, peer, true);
    BOOST_CHECK_EQUAL(info.qos.proto, plexus::protocol::udp);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::server);

    peer.udp.force.nat = true;
    peer.tcp.force.nat = true;
    peer.udp.force.variable_address = true;
    peer.tcp.force.variable_address = true;
    host.udp.force.variable_address = true;
    host.tcp.force.variable_address = true;
    host.qos.proto = plexus::protocol::any;

    BOOST_REQUIRE_THROW(plexus::make_contract(udp, tcp, host, peer, true), std::runtime_error);
    BOOST_REQUIRE_THROW(plexus::make_contract(udp, tcp, host, peer, false), std::runtime_error);

    peer.udp.force.variable_address = false;
    peer.tcp.force.variable_address = false;
    host.udp.force.variable_address = false;
    host.tcp.force.variable_address = false;
    peer.udp.force.mapping = plexus::firewall::address_and_port_dependent;
    peer.tcp.force.mapping = plexus::firewall::address_and_port_dependent;
    host.udp.force.mapping = plexus::firewall::address_and_port_dependent;
    host.tcp.force.mapping = plexus::firewall::address_and_port_dependent;

    BOOST_REQUIRE_THROW(plexus::make_contract(udp, tcp, host, peer, true), std::runtime_error);
    BOOST_REQUIRE_THROW(plexus::make_contract(udp, tcp, host, peer, false), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(cone_udp_contract)
{
    tests::make_cone_contract_test(plexus::protocol::udp);
}

BOOST_AUTO_TEST_CASE(cone_tcp_contract)
{
    tests::make_cone_contract_test(plexus::protocol::tcp);
}

BOOST_AUTO_TEST_CASE(cone_ssl_contract)
{
    tests::make_cone_contract_test(plexus::protocol::ssl);
}

BOOST_AUTO_TEST_CASE(cone_any_contract)
{
    plexus::endpoint udp { boost::asio::ip::make_address("192.168.0.1"), 3000 };
    plexus::endpoint tcp { boost::asio::ip::make_address("192.168.0.1"), 4000 };

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

    auto info = plexus::make_contract(udp, tcp, host, peer, true);
    BOOST_CHECK_EQUAL(info.inner, tcp);
    BOOST_CHECK_EQUAL(info.outer, host.tcp.outer);
    BOOST_CHECK_EQUAL(info.alien, peer.tcp.outer);
    BOOST_CHECK_EQUAL(info.secret, 0);
    BOOST_CHECK_EQUAL(info.qos.proto, plexus::protocol::ssl);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

    host.qos.proto = plexus::protocol::tcp;

    info = plexus::make_contract(udp, tcp, host, peer, false);
    BOOST_CHECK_EQUAL(info.inner, tcp);
    BOOST_CHECK_EQUAL(info.outer, host.tcp.outer);
    BOOST_CHECK_EQUAL(info.alien, peer.tcp.outer);
    BOOST_CHECK_EQUAL(info.secret, 0);
    BOOST_CHECK_EQUAL(info.qos.proto, plexus::protocol::tcp);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

    host.qos.proto = plexus::protocol::udp;

    info = plexus::make_contract(udp, tcp, host, peer, true);
    BOOST_CHECK_EQUAL(info.inner, udp);
    BOOST_CHECK_EQUAL(info.outer, host.udp.outer);
    BOOST_CHECK_EQUAL(info.alien, peer.udp.outer);
    BOOST_CHECK_EQUAL(info.secret, 0);
    BOOST_CHECK_EQUAL(info.qos.proto, plexus::protocol::udp);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

    host.qos.proto = plexus::protocol::ssl;

    info = plexus::make_contract(udp, tcp, host, peer, false);
    BOOST_CHECK_EQUAL(info.qos.proto, plexus::protocol::ssl);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

    host.qos.proto = plexus::protocol::any;
    peer.udp.force.nat = true;
    peer.tcp.force.nat = true;

    info = plexus::make_contract(udp, tcp, host, peer, true);
    BOOST_CHECK_EQUAL(info.qos.proto, plexus::protocol::udp);
    BOOST_CHECK_EQUAL(info.qos.role, plexus::relation::client);

    host.qos.proto = plexus::protocol::tcp;

    BOOST_REQUIRE_THROW(plexus::make_contract(udp, tcp, host, peer, true), std::runtime_error);
    BOOST_REQUIRE_THROW(plexus::make_contract(udp, tcp, host, peer, false), std::runtime_error); 

    host.qos.proto = plexus::protocol::any;
    peer.udp.force.nat = false;
    peer.tcp.force.nat = false;
    peer.udp.force.filtering = plexus::firewall::address_and_port_dependent;
    peer.tcp.force.filtering = plexus::firewall::address_and_port_dependent;

    BOOST_REQUIRE_THROW(plexus::make_contract(udp, tcp, host, peer, true), std::runtime_error);
    BOOST_REQUIRE_THROW(plexus::make_contract(udp, tcp, host, peer, false), std::runtime_error); 
}
