/*
 * Copyright (c) 2022 Novemus Band. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 */

#include <regex>
#include <thread>
#include <boost/program_options.hpp>
#include <boost/lexical_cast.hpp>
#include "features.h"
#include "utils.h"
#include "log.h"

int main(int argc, char** argv)
{
    boost::program_options::options_description desc("plexus options");
    desc.add_options()
        ("help", "produce help message")
        ("accept", "accept or invite peer for punching initiations")
        ("strategy", boost::program_options::value<std::string>()->default_value("udp"), "udp or tcp")
        ("host-id", boost::program_options::value<std::string>()->required(), "unique plexus identifier of host side")
        ("peer-id", boost::program_options::value<std::string>()->required(), "unique plexus identifier of peer side")
        ("email-smtps", boost::program_options::value<std::string>()->required(), "smtp server used to send reference to a peer")
        ("email-imaps", boost::program_options::value<std::string>()->required(), "imaps server used to receive reference from a peer")
        ("email-login", boost::program_options::value<std::string>()->required(), "login of email account")
        ("email-passwd", boost::program_options::value<std::string>()->required(), "password of email account")
        ("email-from", boost::program_options::value<std::string>()->required(), "email address used by the host")
        ("email-to", boost::program_options::value<std::string>()->required(), "email address used by a peer")
        ("email-cert", boost::program_options::value<std::string>()->default_value(""), "path to X509 certificate of email client")
        ("email-key", boost::program_options::value<std::string>()->default_value(""), "path to Private Key of email client")
        ("email-ca", boost::program_options::value<std::string>()->default_value(""), "path to email Certification Authority")
        ("smime-peer", boost::program_options::value<std::string>()->default_value(""), "path to smime X509 certificate of a peer")
        ("smime-cert", boost::program_options::value<std::string>()->default_value(""), "path to smime X509 certificate of the host")
        ("smime-key", boost::program_options::value<std::string>()->default_value(""), "path to smime Private Key of the host")
        ("smime-ca", boost::program_options::value<std::string>()->default_value(""), "path to smime Certification Authority")
        ("stun-ip", boost::program_options::value<std::string>()->required(), "ip address of stun server")
        ("stun-port", boost::program_options::value<uint16_t>()->default_value(3478), "port of stun server")
        ("bind-ip", boost::program_options::value<std::string>()->required(), "local ip address from which to punch a hole in NAT")
        ("bind-port", boost::program_options::value<uint16_t>()->required(), "local port from which to punch a hole in NAT")
        ("punch-hops", boost::program_options::value<uint16_t>()->default_value(7), "time-to-live parameter for punch packets")
        ("exec-command", boost::program_options::value<std::string>()->required(), "command executed after punching the NAT")
        ("exec-pwd", boost::program_options::value<std::string>()->default_value(""), "working directory for executable")
        ("exec-log-file", boost::program_options::value<std::string>()->default_value(""), "log file for executable")
        ("log-level", boost::program_options::value<uint16_t>()->default_value(plexus::log::debug), "0 - none, 1 - fatal, 2 - error, 3 - warnine, 4 - info, 5 - debug, 6 - trace")
        ("log-file", boost::program_options::value<std::string>()->default_value(""), "plexus log file");

    boost::program_options::variables_map vm;
    boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), vm);

    if(vm.count("help"))
    {
        std::cout << desc;
        return 0;
    }

    try
    {
        boost::program_options::notify(vm);
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
        std::cout << desc;
        return 1;
    }

    boost::program_options::notify(vm);

    try
    {
        plexus::log::set((plexus::log::severity)vm["log-level"].as<uint16_t>(), vm["log-file"].as<std::string>());
        
        auto puncher = vm["strategy"].as<std::string>() == "udp"
            ? plexus::create_udp_puncher(
                plexus::network::endpoint(vm["stun-ip"].as<std::string>(), vm["stun-port"].as<uint16_t>()),
                plexus::network::endpoint(vm["bind-ip"].as<std::string>(), vm["bind-port"].as<uint16_t>()),
                (uint8_t)vm["punch-hops"].as<uint16_t>()
                )
            : plexus::create_tcp_puncher(
                plexus::network::endpoint(vm["stun-ip"].as<std::string>(), vm["stun-port"].as<uint16_t>()),
                plexus::network::endpoint(vm["bind-ip"].as<std::string>(), vm["bind-port"].as<uint16_t>()),
                (uint8_t)vm["punch-hops"].as<uint16_t>()
                );

        plexus::traverse state = puncher->explore_network();
        if (state.mapping != plexus::independent)
        {
            _err_ << "network configuration does not allow to establish peer connection";
            return -1;
        }

        auto mediator = plexus::create_email_mediator(
            vm["host-id"].as<std::string>(),
            vm["peer-id"].as<std::string>(),
            vm["email-smtps"].as<std::string>(),
            vm["email-imaps"].as<std::string>(),
            vm["email-login"].as<std::string>(),
            vm["email-passwd"].as<std::string>(),
            vm["email-from"].as<std::string>(),
            vm["email-to"].as<std::string>(),
            vm["email-cert"].as<std::string>(),
            vm["email-key"].as<std::string>(),
            vm["email-ca"].as<std::string>(),
            vm["smime-peer"].as<std::string>(),
            vm["smime-cert"].as<std::string>(),
            vm["smime-key"].as<std::string>(),
            vm["smime-ca"].as<std::string>()
            );

        auto executor = [&](const plexus::network::endpoint& host, const plexus::network::endpoint& peer)
        {
            std::string args = plexus::utils::format("%s %d %s %d %s %d",
                vm["bind-ip"].as<std::string>().c_str(),
                vm["bind-port"].as<uint16_t>(),
                host.first.c_str(),
                host.second,
                peer.first.c_str(),
                peer.second
                );

            plexus::exec(
                vm["exec-command"].as<std::string>(),
                args,
                vm["exec-pwd"].as<std::string>(),
                vm["exec-log-file"].as<std::string>()
                );
        };

        do
        {
            try
            {
                if (vm.count("accept"))
                {
                    plexus::reference peer = mediator->receive_request();
                    plexus::reference host = std::make_pair(
                        puncher->punch_hole_to_peer(peer.first),
                        plexus::utils::random<uint64_t>()
                        );
                    mediator->dispatch_response(host);
                    puncher->await_peer(peer.first, peer.second ^ host.second);

                    executor(host.first, peer.first);
                }
                else
                {
                    plexus::reference host = std::make_pair(
                        puncher->obtain_endpoint(),
                        plexus::utils::random<uint64_t>()
                        );
                    mediator->dispatch_request(host);
                    plexus::reference peer = mediator->receive_response();
                    puncher->reach_peer(peer.first, peer.second ^ host.second);

                    executor(host.first, peer.first);
                }
            }
            catch (const plexus::timeout_error& ex)
            {
                _err_ << ex.what();
            }
            catch (const plexus::handshake_error& ex)
            {
                _err_ << ex.what();
            }
        } 
        while (vm.count("accept"));
    }
    catch(const std::exception& e)
    {
        _ftl_ << e.what();
    }

    return 0;
}
