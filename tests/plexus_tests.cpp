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
    class context
    {
        std::string m_app;
        std::string m_repo;
        plexus::identity m_host;
        plexus::identity m_peer;
        plexus::emailer m_emailer;
        plexus::dhtnode m_dhtnode;
        plexus::endpoint m_stun;
        uint16_t m_hops;

    public:

        context()
        {
            wormhole::log::set(wormhole::log::debug);

            m_app = "plexus_test_app";
            m_host.owner = plexus::utils::getenv<std::string>("EMAIL_LOGIN", "");
            m_host.pin = "host";
            m_peer.owner = plexus::utils::getenv<std::string>("EMAIL_LOGIN", "");
            m_peer.pin = "peer";

            m_emailer = plexus::emailer {
                plexus::utils::getenv<plexus::endpoint>("SMTP_SERVER", plexus::endpoint{}),
                plexus::utils::getenv<plexus::endpoint>("IMAP_SERVER", plexus::endpoint{}),
                plexus::utils::getenv<std::string>("EMAIL_LOGIN", ""),
                plexus::utils::getenv<std::string>("IMAIL_PASSWORD", ""),
                "", "", ""
            };

            m_dhtnode = plexus::dhtnode { plexus::utils::getenv<std::string>("DHT_BOOTSTRAP", ""), 0, 0 };

            m_repo = std::filesystem::temp_directory_path().generic_u8string() + "/" + m_app;
            m_stun = plexus::utils::getenv<plexus::endpoint>("STUN_SERVER", plexus::endpoint{});
            m_hops = plexus::utils::getenv<uint16_t>("PUNCH_HOPS", 5);

            auto host_dir = m_repo + "/" + m_host.owner + "/" + m_host.pin;
            auto peer_dir = m_repo + "/" + m_peer.owner + "/" + m_peer.pin;

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

        plexus::options make_config(bool email, plexus::protocol proto, plexus::relation role) const
        {
            return plexus::options {
                m_app,
                m_repo,
                plexus::endpoint {},
                plexus::endpoint {},
                m_stun,
                m_hops,
                plexus::criteria { proto, role },
                email 
                    ? plexus::rendezvous { m_emailer } 
                    : plexus::rendezvous { m_dhtnode }
            };
        }

        void make_stun_test() const
        {
            boost::asio::io_context io;
            plexus::explore_network(io, plexus::endpoint{}, plexus::endpoint{}, m_stun,
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

        void make_rendezvous_test(bool email) const
        {
            auto config = make_config(email, plexus::protocol::udp, plexus::relation::either);
            auto acc = std::async(std::launch::async, [&]()
            {
                boost::asio::io_context io;

                plexus::spawn_accept(io, config, m_host, m_peer, 
                    [&](const plexus::identity& host, const plexus::identity& peer, const plexus::contract& term)
                    {
                        BOOST_CHECK_EQUAL(m_host.owner, host.owner);
                        BOOST_CHECK_EQUAL(m_host.pin, host.pin);
                        BOOST_CHECK_EQUAL(m_peer.owner, peer.owner);
                        BOOST_CHECK_EQUAL(m_peer.pin, peer.pin);
                        BOOST_CHECK_EQUAL(term.qos.proto, plexus::protocol::udp);
                        BOOST_CHECK_EQUAL(term.qos.role, plexus::relation::server);
                        BOOST_CHECK_NE(term.inner, plexus::endpoint{});
                        BOOST_CHECK_NE(term.outer, plexus::endpoint{});
                        BOOST_CHECK_NE(term.alien, plexus::endpoint{});
                        BOOST_CHECK_NE(term.secret, 0);
                        io.stop();
                    },
                    [&](const plexus::identity& host, const plexus::identity& peer, const std::string& error)
                    {
                        BOOST_CHECK_EQUAL(m_host.owner, host.owner);
                        BOOST_CHECK_EQUAL(m_host.pin, host.pin);
                        BOOST_CHECK_EQUAL(m_peer.owner, peer.owner);
                        BOOST_CHECK_EQUAL(m_peer.pin, peer.pin);
                        BOOST_ERROR(error.c_str());
                        io.stop();
                    });

                io.run();
            });

            auto inv = std::async(std::launch::async, [&]()
            {
                boost::asio::io_context io;

                plexus::spawn_invite(io, config, m_peer, m_host, 
                    [&](const plexus::identity& host, const plexus::identity& peer, const plexus::contract& term)
                    {
                        BOOST_CHECK_EQUAL(m_host.owner, peer.owner);
                        BOOST_CHECK_EQUAL(m_host.pin, peer.pin);
                        BOOST_CHECK_EQUAL(m_peer.owner, host.owner);
                        BOOST_CHECK_EQUAL(m_peer.pin, host.pin);
                        BOOST_CHECK_EQUAL(term.qos.proto, plexus::protocol::udp);
                        BOOST_CHECK_EQUAL(term.qos.role, plexus::relation::client);
                        BOOST_CHECK_NE(term.inner, plexus::endpoint{});
                        BOOST_CHECK_NE(term.outer, plexus::endpoint{});
                        BOOST_CHECK_NE(term.alien, plexus::endpoint{});
                        BOOST_CHECK_NE(term.secret, 0);
                        io.stop();
                    },
                    [&](const plexus::identity& host, const plexus::identity& peer, const std::string& error)
                    {
                        BOOST_CHECK_EQUAL(m_host.owner, peer.owner);
                        BOOST_CHECK_EQUAL(m_host.pin, peer.pin);
                        BOOST_CHECK_EQUAL(m_peer.owner, host.owner);
                        BOOST_CHECK_EQUAL(m_peer.pin, host.pin);
                        BOOST_ERROR(error.c_str());
                        io.stop();
                    });

                io.run();
            });

            acc.wait();
            inv.wait();
        }

        void make_advent_test(bool email) const
        {
            auto rcv = std::async(std::launch::async, [&]()
            {
                boost::asio::io_context io;

                plexus::receive_advent(io, email ? plexus::rendezvous { m_emailer } : plexus::rendezvous { m_dhtnode }, m_app, m_repo, m_host, m_peer, 
                    [&](const plexus::identity& h, const plexus::identity& p)
                    {
                        BOOST_CHECK_EQUAL(m_host.owner, h.owner);
                        BOOST_CHECK_EQUAL(m_host.pin, h.pin);
                        BOOST_CHECK_EQUAL(m_peer.owner, p.owner);
                        BOOST_CHECK_EQUAL(m_peer.pin, p.pin);
                        io.stop();
                    },
                    [&](const plexus::identity& h, const plexus::identity& p, const std::string& error)
                    {
                        BOOST_CHECK_EQUAL(m_host.owner, h.owner);
                        BOOST_CHECK_EQUAL(m_host.pin, h.pin);
                        BOOST_CHECK_EQUAL(m_peer.owner, p.owner);
                        BOOST_CHECK_EQUAL(m_peer.pin, p.pin);
                        BOOST_ERROR(error.c_str());
                        io.stop();
                    });

                io.run();
            });

            auto fwd = std::async(std::launch::async, [&]()
            {
                boost::asio::io_context io;

                plexus::forward_advent(io, email ? plexus::rendezvous { m_emailer } : plexus::rendezvous { m_dhtnode }, m_app, m_repo, m_host, m_peer,
                    [&](const plexus::identity& h, const plexus::identity& p)
                    {
                        BOOST_CHECK_EQUAL(m_host.owner, p.owner);
                        BOOST_CHECK_EQUAL(m_host.pin, p.pin);
                        BOOST_CHECK_EQUAL(m_peer.owner, h.owner);
                        BOOST_CHECK_EQUAL(m_peer.pin, h.pin);
                        io.stop();
                    },
                    [&](const plexus::identity& h, const plexus::identity& p, const std::string& error)
                    {
                        BOOST_CHECK_EQUAL(m_host.owner, p.owner);
                        BOOST_CHECK_EQUAL(m_host.pin, p.pin);
                        BOOST_CHECK_EQUAL(m_peer.owner, h.owner);
                        BOOST_CHECK_EQUAL(m_peer.pin, h.pin);
                        BOOST_ERROR(error.c_str());
                        io.stop();
                    });

                io.run();
            });

            rcv.wait();
            fwd.wait();
        }

        template<typename channel> void make_application_test()
        {
            auto proto = std::is_same<channel, tubus::udp_channel>::value ? plexus::protocol::udp : plexus::protocol::tcp;
            auto config = make_config(false, proto, plexus::relation::either);

            auto acc = std::async(std::launch::async, [&]()
            {
                boost::asio::io_context io;
                plexus::spawn_accept(io, config, m_host, m_peer, 
                    [&](const plexus::identity& host, const plexus::identity& peer, const plexus::contract& term)
                    {
                        BOOST_REQUIRE_EQUAL(term.qos.proto, proto);
                        BOOST_REQUIRE_EQUAL(term.qos.role, plexus::relation::server);

                        auto server = channel::create(io, term.secret);
                        server->open(term.inner);
                        server->accept(term.alien, [&, server, term](const boost::system::error_code& ec)
                        {
                            BOOST_REQUIRE_EQUAL(ec, boost::system::error_code());
                            BOOST_CHECK_EQUAL(server->peer(), term.alien);
                            
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
                plexus::spawn_invite(io, config, m_peer, m_host,
                    [&](const plexus::identity& host, const plexus::identity& peer, const plexus::contract& term)
                    {
                        BOOST_REQUIRE_EQUAL(term.qos.proto, proto);
                        BOOST_REQUIRE_EQUAL(term.qos.role, plexus::relation::client);

                        auto client = channel::create(io, term.secret);
                        client->open(term.inner);
                        client->connect(term.alien, [&, client, term](const boost::system::error_code& ec)
                        {
                            BOOST_REQUIRE_EQUAL(ec, boost::system::error_code());
                            BOOST_CHECK_EQUAL(client->peer(), term.alien);

                            tubus::const_buffer wb("client");
                            client->write(wb, [&, client, wb](const boost::system::error_code& ec, size_t size)
                            {
                                BOOST_REQUIRE_EQUAL(ec, boost::system::error_code());
                                BOOST_REQUIRE_EQUAL(size, wb.size());

                                tubus::mutable_buffer rb(std::strlen("server"));
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
    };

    boost::test_tools::assertion_result is_emailer_context_defined(boost::unit_test::test_unit_id)
    {
        return std::getenv("EMAIL_LOGIN") != nullptr && std::getenv("EMAIL_PASSWORD") != nullptr
            && std::getenv("SMTP_SERVER") != nullptr && std::getenv("IMAP_SERVER") != nullptr 
            && std::getenv("STUN_SERVER") != nullptr;
    }

    boost::test_tools::assertion_result is_dhtnode_context_defined(boost::unit_test::test_unit_id)
    {
        return std::getenv("EMAIL_LOGIN") != nullptr && std::getenv("EMAIL_PASSWORD") != nullptr
            && std::getenv("DHT_BOOTSTRAP") != nullptr && std::getenv("STUN_SERVER") != nullptr;
    }
}

// These tests are for only debugging, run them manually in the suitable context.
// Current version was tested with the firewall described below.
//
//      nat:                true
//      hairpin:            true
//      random_port:        true
//      variable_address:   false
//      mapping:            independent
//      variable_address:   adress_and_port_dependent
//
// Theese features meet to both UDP and TCP traverse. STUN server must support both protocols.

BOOST_FIXTURE_TEST_SUITE(plexus, tests::context)

BOOST_AUTO_TEST_CASE(stun_test, *boost::unit_test::precondition(tests::is_dhtnode_context_defined))
{
    BOOST_TEST_MESSAGE("testing plexus stun client...");
    make_stun_test();
}

BOOST_AUTO_TEST_CASE(email_rendezvous, *boost::unit_test::precondition(tests::is_emailer_context_defined))
{
    BOOST_TEST_MESSAGE("testing plexus email rendezvous...");
    make_rendezvous_test(true);
}

BOOST_AUTO_TEST_CASE(dht_rendezvous, *boost::unit_test::precondition(tests::is_dhtnode_context_defined))
{
    BOOST_TEST_MESSAGE("testing plexus dht rendezvous...");
    make_rendezvous_test(false);
}

BOOST_AUTO_TEST_CASE(email_advent, *boost::unit_test::precondition(tests::is_emailer_context_defined))
{
    BOOST_TEST_MESSAGE("testing plexus email advent...");
    make_advent_test(true);
}

BOOST_AUTO_TEST_CASE(dht_advent, *boost::unit_test::precondition(tests::is_dhtnode_context_defined))
{
    BOOST_TEST_MESSAGE("testing plexus dht advent...");
    make_advent_test(false);
}

BOOST_AUTO_TEST_CASE(udp_application, *boost::unit_test::precondition(tests::is_dhtnode_context_defined))
{
    BOOST_TEST_MESSAGE("testing plexus udp application...");
    make_application_test<tubus::udp_channel>();
}

BOOST_AUTO_TEST_CASE(tcp_application, *boost::unit_test::precondition(tests::is_dhtnode_context_defined))
{
    BOOST_TEST_MESSAGE("testing plexus tcp application...");
    make_application_test<tubus::tcp_channel>();
}

BOOST_AUTO_TEST_SUITE_END()
