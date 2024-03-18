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
#include <boost/program_options.hpp>
#include <boost/regex.hpp>

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
        ("email-smtps", boost::program_options::value<smtp_server_endpoint>()->required(), "smtps server used to send reference to the peer")
        ("email-imaps", boost::program_options::value<imap_server_endpoint>()->required(), "imaps server used to receive reference from the peer")
        ("email-login", boost::program_options::value<std::string>()->required(), "login of email account")
        ("email-password", boost::program_options::value<std::string>()->required(), "password of email account")
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
            std::cout << desc;
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
                return boost::regex_replace(line,
                    boost::regex("(%innerip%)|(%innerport%)|(%outerip%)|(%outerport%)|(%peerip%)|(%peerport%)|(%secret%)|(%hostpin%)|(%peerpin%)|(%hostemail%)|(%peeremail%)"),
                    plexus::utils::format("(?{1}%s)(?{2}%u)(?{3}%s)(?{4}%u)(?{5}%s)(?{6}%u)(?{7}%llu)(?{8}%s)(?{9}%s)(?{10}%s)(?{11}%s)",
                        bind.address().to_string().c_str(),
                        bind.port(),
                        gateway.endpoint.address().to_string().c_str(),
                        gateway.endpoint.port(),
                        faraway.endpoint.address().to_string().c_str(),
                        faraway.endpoint.port(),
                        gateway.puzzle ^ faraway.puzzle,
                        host.pin.c_str(),
                        peer.pin.c_str(),
                        host.owner.c_str(),
                        peer.owner.c_str()),
                    boost::match_posix | boost::format_all
                    );
            };

            plexus::exec(
                vm["exec-command"].as<std::string>(),
                format(vm["exec-args"].as<std::string>()),
                format(vm["exec-pwd"].as<std::string>()),
                format(vm["exec-log"].as<std::string>())
                );
        };

        plexus::options config = { plexus::mediator {
                vm["app-id"].as<std::string>(),
                vm["app-repo"].as<std::string>(),
                vm["email-smtps"].as<smtp_server_endpoint>(),
                vm["email-imaps"].as<imap_server_endpoint>(),
                vm["email-login"].as<std::string>(),
                vm["email-password"].as<std::string>(),
                vm["email-cert"].as<std::string>(),
                vm["email-key"].as<std::string>(),
                vm["email-ca"].as<std::string>() 
            },
            vm["stun-server"].as<stun_server_endpoint>(),
            vm["stun-client"].as<stun_client_endpoint>(),
            vm["punch-hops"].as<uint16_t>()
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
