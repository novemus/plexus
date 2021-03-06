/*
 * Copyright (c) 2022 Novemus Band. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * 
 */

#include <regex>
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
        ("stun-port", boost::program_options::value<uint16_t>()->default_value(3478u), "port of stun server")
        ("bind-ip", boost::program_options::value<std::string>()->required(), "local ip address from which to punch a udp hole")
        ("bind-port", boost::program_options::value<uint16_t>()->required(), "local port from which to punch a udp hole")
        ("punch-timeout", boost::program_options::value<int64_t>()->default_value(60), "timeout (seconds) to punch udp hole to a peer")
        ("exec-command", boost::program_options::value<std::string>()->required(), "command to execute after the udp hole to a peer is punched")
        ("exec-pwd", boost::program_options::value<std::string>()->default_value(""), "working directory for executable")
        ("exec-log-file", boost::program_options::value<std::string>()->default_value(""), "log file for executable")
        ("retry-timeout", boost::program_options::value<int64_t>()->default_value(20), "timeout (seconds) for retrying to reach a peer")
        ("retry-count", boost::program_options::value<uint64_t>()->default_value(3), "number of attempts to reach a peer")
        ("accept", "accept punching initiations from a peer infinitely")
        ("log-level", boost::program_options::value<int>()->default_value(plexus::log::debug), "0 - none, 1 - fatal, 2 - error, 3 - warnine, 4 - info, 5 - debug, 6 - trace")
        ("log-file", boost::program_options::value<std::string>()->default_value(""), "plexus log file");

    boost::program_options::variables_map vm;
    boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), vm);
    boost::program_options::notify(vm);

    if(vm.count("help"))
    {
        std::cout << desc;
        return 0;
    }

    try
    {
        plexus::log::set((plexus::log::severity)vm["log-level"].as<int>(), vm["log-file"].as<std::string>());

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

        auto puncher = plexus::create_stun_puncher(
            plexus::network::endpoint(vm["stun-ip"].as<std::string>(), vm["stun-port"].as<uint16_t>()),
            plexus::network::endpoint(vm["bind-ip"].as<std::string>(), vm["bind-port"].as<uint16_t>())
            );

        plexus::traverse state = puncher->explore_network();
        if (state.mapping != plexus::independent)
        {
            _err_ << "network configuration does not allow to establish peer connection";
            return -1;
        }

        uint64_t tries = vm["retry-count"].as<uint64_t>();
        int64_t delay = vm["retry-timeout"].as<int64_t>();
        bool accept = vm.count("accept") > 0;

        do
        {
            if (accept)
                mediator->accept();

            uint64_t puzzle = plexus::utils::random();

            do
            {
                try
                {
                    plexus::reference host(puncher->punch_udp_hole(), puzzle);
                    plexus::reference peer = mediator->exchange(host);

                    puncher->punch_hole_to_peer(peer.first, host.second ^ peer.second, vm["punch-timeout"].as<int64_t>() * 1000);

                    std::string args = plexus::utils::format("%s %d %s %d %s %d",
                        vm["bind-ip"].as<std::string>().c_str(),
                        vm["bind-port"].as<uint16_t>(),
                        host.first.first.c_str(),
                        host.first.second,
                        peer.first.first.c_str(),
                        peer.first.second
                        );

                    plexus::exec(
                        vm["exec-command"].as<std::string>(),
                        args,
                        vm["exec-pwd"].as<std::string>(),
                        vm["exec-log-file"].as<std::string>()
                        );

                    if (accept)
                        break;

                    return 0;
                }
                catch(const plexus::timeout_error& ex)
                {
                    _err_ << ex.what();
                }
                catch(const plexus::handshake_error& ex)
                {
                    _err_ << ex.what();
                }
                catch(const plexus::incomplete_error& ex)
                {
                    _err_ << ex.what();
                }

                std::this_thread::sleep_for(std::chrono::seconds(delay));
            }
            while (--tries > 0);

        } while (accept);
    }
    catch(const std::exception& e)
    {
        _ftl_ << e.what();
    }

    return 0;
}
