/*
 * Copyright (c) 2022 Novemus Band. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 */

#include "features.h"
#include "plexus.h"
#include "utils.h"
#include <logger.h>
#include <regex>
#include <boost/program_options.hpp>

template<class proto, const char* service>
struct endpoint : public boost::asio::ip::basic_endpoint<proto>
{
    endpoint() {}
    endpoint(const boost::asio::ip::basic_endpoint<proto>& ep) : boost::asio::ip::basic_endpoint<proto>(ep) {}
};

constexpr char stun_server_default_port[] = "3478";
constexpr char stun_client_default_port[] = "1974";
constexpr char smtp_server_default_port[] = "smtps";
constexpr char imap_client_default_port[] = "imaps";

using stun_server_endpoint = endpoint<boost::asio::ip::udp, stun_server_default_port>;
using stun_client_endpoint = endpoint<boost::asio::ip::udp, stun_client_default_port>;
using smtp_server_endpoint = endpoint<boost::asio::ip::tcp, smtp_server_default_port>;
using imap_server_endpoint = endpoint<boost::asio::ip::tcp, imap_client_default_port>;

template<class proto, const char* service>
void validate(boost::any& result, const std::vector<std::string>& values, endpoint<proto, service>*, int)
{
    boost::program_options::validators::check_first_occurrence(result);
    const std::string& url = boost::program_options::validators::get_single_string(values);

    try
    {
        result = endpoint<proto, service>(
            plexus::utils::parse_endpoint<boost::asio::ip::basic_endpoint<proto>>(url, service)
            );
    }
    catch(const boost::system::system_error&)
    {
        boost::throw_exception(boost::program_options::error("can't resolve " + url));
    }
}

int main(int argc, char** argv)
{
    boost::program_options::options_description desc("plexus options");
    desc.add_options()
        ("help", "produce help message")
        ("accept", boost::program_options::bool_switch(), "accept or invite peer to initiate connection")
        ("app-id", boost::program_options::value<std::string>()->required(), "identifier of the application")
        ("app-repo", boost::program_options::value<std::string>()->default_value(""), "path to application repository")
        ("host-info", boost::program_options::value<plexus::identity>()->default_value(plexus::identity()), "identifier of the host: <email/pin>")
        ("peer-info", boost::program_options::value<plexus::identity>()->default_value(plexus::identity()), "identifier of the peer: <email/pin>")
        ("stun-server", boost::program_options::value<stun_server_endpoint>()->required(), "endpoint of public stun server")
        ("stun-client", boost::program_options::value<stun_client_endpoint>()->required(), "endpoint of local stun client")
        ("dht-bootstrap", boost::program_options::value<std::string>()->default_value("bootstrap.jami.net:4222"), "url of bootstrap DHT service")
        ("dht-port", boost::program_options::value<uint16_t>()->default_value(4222), "local port to bind DHT node")
        ("dht-network", boost::program_options::value<uint32_t>()->default_value(0), "DHT network id")
        ("email-smtps", boost::program_options::value<smtp_server_endpoint>(), "smtps server used to send reference to the peer")
        ("email-imaps", boost::program_options::value<imap_server_endpoint>(), "imaps server used to receive reference from the peer")
        ("email-login", boost::program_options::value<std::string>(), "login of email account")
        ("email-password", boost::program_options::value<std::string>(), "password of email account")
        ("email-cert", boost::program_options::value<std::string>()->default_value(""), "path to X509 certificate of email client")
        ("email-key", boost::program_options::value<std::string>()->default_value(""), "path to Private Key of email client")
        ("email-ca", boost::program_options::value<std::string>()->default_value(""), "path to email Certification Authority")
        ("punch-hops", boost::program_options::value<uint16_t>()->default_value(7), "time-to-live parameter for punch packets")
        ("exec-command", boost::program_options::value<std::string>()->required(), "command executed after punching the NAT")
        ("exec-args", boost::program_options::value<std::string>()->default_value(""), "arguments for the command executed after punching the NAT, allowed wildcards: %innerip%, %innerport%, %outerip%, %outerport%, %peerip%, %peerport%, %secret%, %hostpin%, %peerpin%, %hostemail%, %peeremail%")
        ("exec-pwd", boost::program_options::value<std::string>()->default_value(""), "working directory for executable, the above wildcards are allowed")
        ("exec-log", boost::program_options::value<std::string>()->default_value(""), "exec log file, the above wildcards are allowed")
        ("log-level", boost::program_options::value<wormhole::log::severity>()->default_value(wormhole::log::info), "log level: <fatal|error|warning|info|debug|trace>")
        ("log-file", boost::program_options::value<std::string>()->default_value(""), "plexus log file, allowed %p (process id) wildcard")
        ("config", boost::program_options::value<std::string>(), "path to INI-like configuration file");

    boost::program_options::variables_map vm;
    try
    {
        boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), vm);
        if(vm.count("help"))
        {
            std::cout << desc << std::endl;
            return -1;
        }

        auto count = vm.count("email-smtps") + vm.count("email-imaps") + vm.count("email-login") + vm.count("email-password");
        if(count > 0 && count != 4)
        {
            std::cout << "to use email service for a rendezvous, specify at least 'email-smtps', 'email-imaps', 'email-login' and 'email-password' arguments" << std::endl;
            return -1;
        }

        if(vm.count("config"))
            boost::program_options::store(boost::program_options::parse_config_file<char>(vm["config"].as<std::string>().c_str(), desc), vm);

        boost::program_options::notify(vm);
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
        std::cout << desc;
        return -1;
    }

    try
    {
        wormhole::log::set(vm["log-level"].as<wormhole::log::severity>(), vm["log-file"].as<std::string>());

        _inf_ << "********** plexus **********";

        auto launch = [&](const plexus::identity& host, const plexus::identity& peer, const boost::asio::ip::udp::endpoint& bind, const plexus::reference& gateway, const plexus::reference& faraway)
        {
            auto format = [&](const std::string& line)
            {
                std::string res = line;
                std::vector<std::pair<std::regex, std::string>> replaces = { 
                    { std::regex("%innerip%"), bind.address().to_string() },
                    { std::regex("%innerport%"), std::to_string(bind.port()) },
                    { std::regex("%outerip%"), gateway.endpoint.address().to_string()},
                    { std::regex("%outerport%"), std::to_string(gateway.endpoint.port()) },
                    { std::regex("%peerip%"), faraway.endpoint.address().to_string() },
                    { std::regex("%peerport%"), std::to_string(faraway.endpoint.port()) },
                    { std::regex("%secret%"), std::to_string(gateway.puzzle ^ faraway.puzzle) },
                    { std::regex("%hostpin%"), host.pin },
                    { std::regex("%peerpin%"), peer.pin },
                    { std::regex("%hostemail%"), host.owner },
                    { std::regex("%peeremail%"), peer.owner }
                };

                for (const auto& item : replaces)
                {
                    res = std::regex_replace(res, item.first, item.second);
                }

                return res;
            };

            plexus::exec(
                vm["exec-command"].as<std::string>(),
                format(vm["exec-args"].as<std::string>()),
                format(vm["exec-pwd"].as<std::string>()),
                format(vm["exec-log"].as<std::string>())
                );
        };

        plexus::options config = {
            vm["app-id"].as<std::string>(),
            vm["app-repo"].as<std::string>(),
            vm["stun-server"].as<stun_server_endpoint>(),
            vm["stun-client"].as<stun_client_endpoint>(),
            vm["punch-hops"].as<uint16_t>(),
            vm.count("email-smtps")
                ? plexus::rendezvous {
                    plexus::emailer {
                        vm["email-smtps"].as<smtp_server_endpoint>(),
                        vm["email-imaps"].as<imap_server_endpoint>(),
                        vm["email-login"].as<std::string>(),
                        vm["email-password"].as<std::string>(),
                        vm["email-cert"].as<std::string>(),
                        vm["email-key"].as<std::string>(),
                        vm["email-ca"].as<std::string>() 
                    }}
                : plexus::rendezvous {
                    plexus::dhtnode {
                        vm["dht-bootstrap"].as<std::string>(),
                        vm["dht-port"].as<uint16_t>(),
                        vm["dht-network"].as<uint32_t>() 
                    }}
        };

        boost::asio::io_service io;
        vm["accept"].as<bool>()
            ? plexus::spawn_accept(io, config, vm["host-info"].as<plexus::identity>(), vm["peer-info"].as<plexus::identity>(), launch)
            : plexus::spawn_invite(io, config, vm["host-info"].as<plexus::identity>(), vm["peer-info"].as<plexus::identity>(), launch);
        io.run();
    }
    catch(const std::exception& e)
    {
        _ftl_ << e.what();
        return -1;
    }

    return 0;
}
