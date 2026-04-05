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

using namespace plexus;

namespace tests
{
    void make_base_contract_test(protocol proto)
    {
        endpoint bind { boost::asio::ip::make_address("192.168.0.1"), 3000 };

        reference host;
        auto& hmap = proto == protocol::udp ? host.udp : host.tcp;
        hmap.outer = endpoint { boost::asio::ip::make_address("10.0.0.3"), 3000 };
        hmap.force = firewall { true, true, true, false, firewall::independent, firewall::address_and_port_dependent };
        host.qos = criteria { proto, schema::either };
        host.puzzle = 1234567890;

        reference peer;
        auto& pmap = proto == protocol::udp ? peer.udp : peer.tcp;
        pmap.outer = endpoint { boost::asio::ip::make_address("10.0.0.3"), 4000 };
        pmap.force = firewall { true, true, true, false, firewall::independent, firewall::address_and_port_dependent };
        peer.qos = criteria { proto, schema::either };
        peer.puzzle = 1234567890;

        auto info = plexus::make_contract(bind, bind, host, peer, true);
        BOOST_CHECK_EQUAL(info.inner, bind);
        BOOST_CHECK_EQUAL(info.outer, hmap.outer);
        BOOST_CHECK_EQUAL(info.alien, pmap.outer);
        BOOST_CHECK_EQUAL(info.secret, 0);
        BOOST_CHECK_EQUAL(info.qos.proto, proto);
        BOOST_CHECK_EQUAL(info.qos.role, schema::server);

        info = plexus::make_contract(bind, bind, host, peer, false);
        BOOST_CHECK_EQUAL(info.qos.proto, proto);
        BOOST_CHECK_EQUAL(info.qos.role, schema::client);

        host.qos.role = schema::server;
        peer.qos.role = schema::client;
        info = plexus::make_contract(bind, bind, host, peer, true);
        BOOST_CHECK_EQUAL(info.qos.proto, proto);
        BOOST_CHECK_EQUAL(info.qos.role, schema::server);

        info = plexus::make_contract(bind, bind, host, peer, false);
        BOOST_CHECK_EQUAL(info.qos.proto, proto);
        BOOST_CHECK_EQUAL(info.qos.role, schema::server);

        host.qos.role = schema::client;
        peer.qos.role = schema::server;
        info = plexus::make_contract(bind, bind, host, peer, true);
        BOOST_CHECK_EQUAL(info.qos.proto, proto);
        BOOST_CHECK_EQUAL(info.qos.role, schema::client);

        info = plexus::make_contract(bind, bind, host, peer, false);
        BOOST_CHECK_EQUAL(info.qos.proto, proto);
        BOOST_CHECK_EQUAL(info.qos.role, schema::client);

        host.qos.role = schema::mutual;
        peer.qos.role = schema::mutual;
        info = plexus::make_contract(bind, bind, host, peer, false);
        BOOST_CHECK_EQUAL(info.qos.proto, proto);
        BOOST_CHECK_EQUAL(info.qos.role, schema::mutual);

        peer.qos.role = schema::either;
        info = plexus::make_contract(bind, bind, host, peer, true);
        BOOST_CHECK_EQUAL(info.qos.proto, proto);
        BOOST_CHECK_EQUAL(info.qos.role, schema::mutual);

        peer.qos.role = schema::server;
        BOOST_REQUIRE_THROW(plexus::make_contract(bind, bind, host, peer, true), std::runtime_error);

        peer.qos.role = schema::client;
        BOOST_REQUIRE_THROW(plexus::make_contract(bind, bind, host, peer, false), std::runtime_error);

        host.qos.role = schema::server;
        peer.qos.role = schema::server;
        BOOST_REQUIRE_THROW(plexus::make_contract(bind, bind, host, peer, true), std::runtime_error);

        host.qos.role = schema::either;
        peer.qos.role = schema::either;
        host.qos.proto = proto == protocol::any ? protocol::udp : proto;
        peer.qos.proto = proto == protocol::any ? protocol::tcp : protocol(proto + 1);
        BOOST_REQUIRE_THROW(plexus::make_contract(bind, bind, host, peer, false), std::runtime_error);

        host.qos.proto = proto;
        peer.qos.proto = proto;
        host.qos.role = schema::server;
        peer.qos.role = schema::either;
        hmap.force.mapping = firewall::address_and_port_dependent;
        BOOST_REQUIRE_THROW(plexus::make_contract(bind, bind, host, peer, true), std::runtime_error);

        host.qos.role = schema::either;
        pmap.force.mapping = firewall::independent;
        pmap.force.mapping = firewall::independent;
        pmap.force.hairpin = false;
        hmap.force.hairpin = false;
        hmap.outer.address = pmap.outer.address;
        BOOST_REQUIRE_THROW(plexus::make_contract(bind, bind, host, peer, false), std::runtime_error);
    }

    void make_cone_contract_test(protocol proto)
    {
        endpoint bind { boost::asio::ip::make_address("192.168.0.1"), 3000 };

        reference host;
        auto& hmap = proto == protocol::udp ? host.udp : host.tcp;
        hmap.outer = endpoint { boost::asio::ip::make_address("10.0.0.2"), 3000 };
        hmap.force = firewall { true, true, true, true, firewall::address_and_port_dependent, firewall::address_and_port_dependent };
        host.qos = criteria { proto, schema::either };
        host.puzzle = 1234567890;

        reference peer;
        auto& pmap = proto == protocol::udp ? peer.udp : peer.tcp;
        pmap.outer = endpoint { boost::asio::ip::make_address("10.0.0.3"), 4000 };
        pmap.force = firewall { true, true, true, false, firewall::independent, firewall::independent };
        peer.qos = criteria { proto, schema::either };
        peer.puzzle = 1234567890;

        auto info = plexus::make_contract(bind, bind, host, peer, true);
        BOOST_CHECK_EQUAL(info.inner, bind);
        BOOST_CHECK_EQUAL(info.outer, hmap.outer);
        BOOST_CHECK_EQUAL(info.alien, pmap.outer);
        BOOST_CHECK_EQUAL(info.secret, 0);
        BOOST_CHECK_EQUAL(info.qos.proto, proto);
        BOOST_CHECK_EQUAL(info.qos.role, schema::client);

        info = plexus::make_contract(bind, bind, host, peer, false);
        BOOST_CHECK_EQUAL(info.qos.proto, proto);
        BOOST_CHECK_EQUAL(info.qos.role, schema::client);

        host.qos.role = schema::client;
        peer.qos.role = schema::server;

        info = plexus::make_contract(bind, bind, host, peer, true);
        BOOST_CHECK_EQUAL(info.qos.proto, proto);
        BOOST_CHECK_EQUAL(info.qos.role, schema::client);

        info = plexus::make_contract(bind, bind, host, peer, false);
        BOOST_CHECK_EQUAL(info.qos.proto, proto);
        BOOST_CHECK_EQUAL(info.qos.role, schema::client);

        host.qos.role = schema::either;
        peer.qos.role = schema::either;
        hmap.force.variable_address = false;
        hmap.force.filtering = firewall::independent;
        hmap.force.mapping = firewall::independent;
        pmap.force.filtering = firewall::address_and_port_dependent;
        pmap.force.mapping = firewall::address_and_port_dependent;

        info = plexus::make_contract(bind, bind, host, peer, true);
        BOOST_CHECK_EQUAL(info.qos.proto, proto);
        BOOST_CHECK_EQUAL(info.qos.role, schema::server);

        info = plexus::make_contract(bind, bind, host, peer, false);
        BOOST_CHECK_EQUAL(info.qos.proto, proto);
        BOOST_CHECK_EQUAL(info.qos.role, schema::server);

        host.qos.role = schema::server;
        peer.qos.role = schema::client;

        info = plexus::make_contract(bind, bind, host, peer, true);
        BOOST_CHECK_EQUAL(info.qos.proto, proto);
        BOOST_CHECK_EQUAL(info.qos.role, schema::server);

        info = plexus::make_contract(bind, bind, host, peer, false);
        BOOST_CHECK_EQUAL(info.qos.proto, proto);
        BOOST_CHECK_EQUAL(info.qos.role, schema::server);

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
        hmap.force.filtering = firewall::independent;
        hmap.force.mapping = firewall::address_and_port_dependent;
        BOOST_REQUIRE_THROW(plexus::make_contract(bind, bind, host, peer, true), std::runtime_error);

        hmap.force.filtering = firewall::address_and_port_dependent;
        hmap.force.mapping = firewall::independent;
        BOOST_REQUIRE_THROW(plexus::make_contract(bind, bind, host, peer, false), std::runtime_error);

        hmap.force.filtering = firewall::address_and_port_dependent;
        hmap.force.mapping = firewall::address_and_port_dependent;
        BOOST_REQUIRE_THROW(plexus::make_contract(bind, bind, host, peer, false), std::runtime_error);
    }
}

BOOST_AUTO_TEST_CASE(simple_udp_contract)
{
    tests::make_base_contract_test(protocol::udp);
}

BOOST_AUTO_TEST_CASE(simple_tcp_contract)
{
    tests::make_base_contract_test(protocol::tcp);
}

BOOST_AUTO_TEST_CASE(simple_ssl_contract)
{
    tests::make_base_contract_test(protocol::ssl);
}

BOOST_AUTO_TEST_CASE(simple_any_contract)
{
    endpoint udp { boost::asio::ip::make_address("192.168.0.1"), 3000 };
    endpoint tcp { boost::asio::ip::make_address("192.168.0.1"), 4000 };

    reference host {
        reference::map {
            endpoint { boost::asio::ip::make_address("10.0.0.2"), 3000 },
            firewall { true, true, true, false, firewall::independent, firewall::address_and_port_dependent }
        },
        reference::map {
            endpoint { boost::asio::ip::make_address("10.0.0.2"), 4000 },
            firewall { true, true, true, false, firewall::independent, firewall::address_and_port_dependent }
        },
        criteria { protocol::any, schema::either },
        1234567890
    };

    reference peer {
        reference::map {
            endpoint { boost::asio::ip::make_address("10.0.0.3"), 4000 },
            firewall { true, true, true, false, firewall::independent, firewall::address_and_port_dependent }
        },
        reference::map {
            endpoint { boost::asio::ip::make_address("10.0.0.3"), 5000 },
            firewall { true, true, true, false, firewall::independent, firewall::address_and_port_dependent }
        },
        criteria { protocol::any, schema::either },
        1234567890
    };

    auto info = plexus::make_contract(udp, tcp, host, peer, true);
    BOOST_CHECK_EQUAL(info.inner, udp);
    BOOST_CHECK_EQUAL(info.outer, host.udp.outer);
    BOOST_CHECK_EQUAL(info.alien, peer.udp.outer);
    BOOST_CHECK_EQUAL(info.secret, 0);
    BOOST_CHECK_EQUAL(info.qos.proto, protocol::udp);
    BOOST_CHECK_EQUAL(info.qos.role, schema::server);

    peer.qos.proto = protocol::tcp;

    info = plexus::make_contract(udp, tcp, host, peer, true);
    BOOST_CHECK_EQUAL(info.inner, tcp);
    BOOST_CHECK_EQUAL(info.outer, host.tcp.outer);
    BOOST_CHECK_EQUAL(info.alien, peer.tcp.outer);
    BOOST_CHECK_EQUAL(info.secret, 0);
    BOOST_CHECK_EQUAL(info.qos.proto, protocol::tcp);
    BOOST_CHECK_EQUAL(info.qos.role, schema::client);

    peer.qos.proto = protocol::ssl;

    info = plexus::make_contract(udp, tcp, host, peer, true);
    BOOST_CHECK_EQUAL(info.inner, tcp);
    BOOST_CHECK_EQUAL(info.outer, host.tcp.outer);
    BOOST_CHECK_EQUAL(info.alien, peer.tcp.outer);
    BOOST_CHECK_EQUAL(info.secret, 0);
    BOOST_CHECK_EQUAL(info.qos.proto, protocol::ssl);
    BOOST_CHECK_EQUAL(info.qos.role, schema::client);

    peer.qos.proto = protocol::any;
    peer.udp.force.nat = false;
    peer.tcp.force.nat = false;

    info = plexus::make_contract(udp, tcp, host, peer, false);
    BOOST_CHECK_EQUAL(info.qos.proto, protocol::ssl);
    BOOST_CHECK_EQUAL(info.qos.role, schema::client);

    host.qos.proto = protocol::udp;

    info = plexus::make_contract(udp, tcp, host, peer, true);
    BOOST_CHECK_EQUAL(info.qos.proto, protocol::udp);
    BOOST_CHECK_EQUAL(info.qos.role, schema::server);

    peer.udp.force.nat = true;
    peer.tcp.force.nat = true;
    peer.udp.force.variable_address = true;
    peer.tcp.force.variable_address = true;
    host.udp.force.variable_address = true;
    host.tcp.force.variable_address = true;
    host.qos.proto = protocol::any;

    BOOST_REQUIRE_THROW(plexus::make_contract(udp, tcp, host, peer, true), std::runtime_error);
    BOOST_REQUIRE_THROW(plexus::make_contract(udp, tcp, host, peer, false), std::runtime_error);

    peer.udp.force.variable_address = false;
    peer.tcp.force.variable_address = false;
    host.udp.force.variable_address = false;
    host.tcp.force.variable_address = false;
    peer.udp.force.mapping = firewall::address_and_port_dependent;
    peer.tcp.force.mapping = firewall::address_and_port_dependent;
    host.udp.force.mapping = firewall::address_and_port_dependent;
    host.tcp.force.mapping = firewall::address_and_port_dependent;

    BOOST_REQUIRE_THROW(plexus::make_contract(udp, tcp, host, peer, true), std::runtime_error);
    BOOST_REQUIRE_THROW(plexus::make_contract(udp, tcp, host, peer, false), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(cone_udp_contract)
{
    tests::make_cone_contract_test(protocol::udp);
}

BOOST_AUTO_TEST_CASE(cone_tcp_contract)
{
    tests::make_cone_contract_test(protocol::tcp);
}

BOOST_AUTO_TEST_CASE(cone_ssl_contract)
{
    tests::make_cone_contract_test(protocol::ssl);
}

BOOST_AUTO_TEST_CASE(cone_any_contract)
{
    endpoint udp { boost::asio::ip::make_address("192.168.0.1"), 3000 };
    endpoint tcp { boost::asio::ip::make_address("192.168.0.1"), 4000 };

    reference host {
        reference::map {
            endpoint { boost::asio::ip::make_address("10.0.0.2"), 3000 },
            firewall { true, true, true, true, firewall::address_and_port_dependent, firewall::address_and_port_dependent }
        },
        reference::map {
            endpoint { boost::asio::ip::make_address("10.0.0.2"), 4000 },
            firewall { true, true, true, true, firewall::address_and_port_dependent, firewall::address_and_port_dependent }
        },
        criteria { protocol::any, schema::either },
        1234567890
    };

    reference peer {
        reference::map {
            endpoint { boost::asio::ip::make_address("10.0.0.3"), 4000 },
            firewall { false, true, false, false, firewall::independent, firewall::independent }
        },
        reference::map {
            endpoint { boost::asio::ip::make_address("10.0.0.3"), 5000 },
            firewall { false, true, false, false, firewall::independent, firewall::independent }
        },
        criteria { protocol::any, schema::either },
        1234567890
    };

    auto info = plexus::make_contract(udp, tcp, host, peer, true);
    BOOST_CHECK_EQUAL(info.inner, tcp);
    BOOST_CHECK_EQUAL(info.outer, host.tcp.outer);
    BOOST_CHECK_EQUAL(info.alien, peer.tcp.outer);
    BOOST_CHECK_EQUAL(info.secret, 0);
    BOOST_CHECK_EQUAL(info.qos.proto, protocol::ssl);
    BOOST_CHECK_EQUAL(info.qos.role, schema::client);

    host.qos.proto = protocol::tcp;

    info = plexus::make_contract(udp, tcp, host, peer, false);
    BOOST_CHECK_EQUAL(info.inner, tcp);
    BOOST_CHECK_EQUAL(info.outer, host.tcp.outer);
    BOOST_CHECK_EQUAL(info.alien, peer.tcp.outer);
    BOOST_CHECK_EQUAL(info.secret, 0);
    BOOST_CHECK_EQUAL(info.qos.proto, protocol::tcp);
    BOOST_CHECK_EQUAL(info.qos.role, schema::client);

    host.qos.proto = protocol::udp;

    info = plexus::make_contract(udp, tcp, host, peer, true);
    BOOST_CHECK_EQUAL(info.inner, udp);
    BOOST_CHECK_EQUAL(info.outer, host.udp.outer);
    BOOST_CHECK_EQUAL(info.alien, peer.udp.outer);
    BOOST_CHECK_EQUAL(info.secret, 0);
    BOOST_CHECK_EQUAL(info.qos.proto, protocol::udp);
    BOOST_CHECK_EQUAL(info.qos.role, schema::client);

    host.qos.proto = protocol::ssl;
    info = plexus::make_contract(udp, tcp, host, peer, false);
    BOOST_CHECK_EQUAL(info.qos.proto, protocol::ssl);
    BOOST_CHECK_EQUAL(info.qos.role, schema::client);

    peer.udp.force.nat = true;
    peer.tcp.force.nat = true;
    host.qos.proto = protocol::any;
    info = plexus::make_contract(udp, tcp, host, peer, true);
    BOOST_CHECK_EQUAL(info.qos.proto, protocol::udp);
    BOOST_CHECK_EQUAL(info.qos.role, schema::client);

    host.qos.proto = protocol::tcp;
    info = plexus::make_contract(udp, tcp, host, peer, false);
    BOOST_CHECK_EQUAL(info.qos.proto, protocol::tcp);
    BOOST_CHECK_EQUAL(info.qos.role, schema::mutual);

    host.qos.proto = protocol::any;
    peer.udp.force.nat = false;
    peer.tcp.force.nat = false;
    peer.udp.force.filtering = firewall::address_and_port_dependent;
    peer.tcp.force.filtering = firewall::address_and_port_dependent;

    BOOST_REQUIRE_THROW(plexus::make_contract(udp, tcp, host, peer, true), std::runtime_error);
    BOOST_REQUIRE_THROW(plexus::make_contract(udp, tcp, host, peer, false), std::runtime_error); 
}
