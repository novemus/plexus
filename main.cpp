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
#include "utils.h"
#include <stdexcept>
#include <thread>
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
        ("accept", boost::program_options::bool_switch(), "accept or invite peer to initiate NAT punching")
        ("app-id", boost::program_options::value<std::string>()->required(), "identifier of the application")
        ("host-id", boost::program_options::value<std::string>()->required(), "unique plexus identifier of the host")
        ("peer-id", boost::program_options::value<std::string>()->required(), "unique plexus identifier of the peer")
        ("host-mail", boost::program_options::value<std::string>()->required(), "email address used by the host")
        ("peer-mail", boost::program_options::value<std::string>()->required(), "email address used by the peer")
        ("cred-repo", boost::program_options::value<std::string>()->default_value(""), "path to credentials repository")
        ("stun-server", boost::program_options::value<stun_server_endpoint>()->required(), "endpoint of public stun server")
        ("stun-client", boost::program_options::value<stun_client_endpoint>()->required(), "endpoint of local stun client")
        ("email-smtps", boost::program_options::value<smtp_server_endpoint>()->required(), "smtps server used to send reference to the peer")
        ("email-imaps", boost::program_options::value<imap_server_endpoint>()->required(), "imaps server used to receive reference from the peer")
        ("email-login", boost::program_options::value<std::string>()->required(), "login of email account")
        ("email-passwd", boost::program_options::value<std::string>()->required(), "password of email account")
        ("email-cert", boost::program_options::value<std::string>()->default_value(""), "path to X509 certificate of email client")
        ("email-key", boost::program_options::value<std::string>()->default_value(""), "path to Private Key of email client")
        ("email-ca", boost::program_options::value<std::string>()->default_value(""), "path to email Certification Authority")
        ("punch-hops", boost::program_options::value<uint16_t>()->default_value(7), "time-to-live parameter for punch packets")
        ("exec-command", boost::program_options::value<std::string>()->required(), "command executed after punching the NAT")
        ("exec-args", boost::program_options::value<std::string>()->default_value(""), "arguments for the command executed after punching the NAT, allowed wildcards: %innerip%, %innerport%, %outerip%, %outerport%, %peerip%, %peerport%, %secret%, %hostid%, %peerid%, %hostmail%, %peermail%")
        ("exec-pwd", boost::program_options::value<std::string>()->default_value(""), "working directory for executable")
        ("exec-log-file", boost::program_options::value<std::string>()->default_value(""), "log file for executable")
        ("log-level", boost::program_options::value<wormhole::log::severity>()->default_value(wormhole::log::info), "log level: <fatal|error|warning|info|debug|trace>")
        ("log-file", boost::program_options::value<std::string>()->default_value(""), "plexus log file")
        ("config", boost::program_options::value<std::string>(), "path to INI-like configuration file");

    boost::program_options::variables_map vm;
    try
    {
        boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), vm);
        if(vm.count("help"))
        {
            std::cout << desc;
            return 0;
        }

        if(vm.count("config"))
            boost::program_options::store(boost::program_options::parse_config_file<char>(vm["config"].as<std::string>().c_str(), desc), vm);

        boost::program_options::notify(vm);
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
        std::cout << desc;
        return 1;
    }

    try
    {
        wormhole::log::set(vm["log-level"].as<wormhole::log::severity>(), false, vm["log-file"].as<std::string>());
        
        boost::asio::ip::udp::endpoint stun = vm["stun-server"].as<stun_server_endpoint>();
        boost::asio::ip::udp::endpoint bind = vm["stun-client"].as<stun_client_endpoint>();

        _dbg_ << "stun server: " << stun;
        _dbg_ << "stun client: " << bind;

        auto puncher = plexus::create_nat_puncher(stun, bind);

        plexus::traverse state = puncher->explore_network();
        if (state.mapping != plexus::independent)
        {
            _err_ << "network configuration does not allow to establish peer connection";
            return -1;
        }

        auto mediator = plexus::create_email_mediator(
            vm["email-smtps"].as<smtp_server_endpoint>(),
            vm["email-imaps"].as<imap_server_endpoint>(),
            vm["email-login"].as<std::string>(),
            vm["email-passwd"].as<std::string>(),
            vm["email-cert"].as<std::string>(),
            vm["email-key"].as<std::string>(),
            vm["email-ca"].as<std::string>(),
            vm["app-id"].as<std::string>(),
            vm["cred-repo"].as<std::string>()
            );

        auto host_info = std::make_pair(vm["host-mail"].as<std::string>(), vm["host-id"].as<std::string>());
        auto peer_info = std::make_pair(vm["peer-mail"].as<std::string>(), vm["peer-id"].as<std::string>());

        auto execute = [&](const boost::asio::ip::udp::endpoint& host, const boost::asio::ip::udp::endpoint& peer, uint64_t secret)
        {
            auto args = vm["exec-args"].as<std::string>();
            if (args.empty())
            {
                args = plexus::utils::format("%s %u %s %u %s %u %llu %s %s %s %s",
                    bind.address().to_string().c_str(),
                    bind.port(),
                    host.address().to_string().c_str(),
                    host.port(),
                    peer.address().to_string().c_str(),
                    peer.port(),
                    secret,
                    host_info.second.c_str(),
                    peer_info.second.c_str(),
                    host_info.first.c_str(),
                    peer_info.first.c_str()
                    );
            }
            else
            {
                args = boost::regex_replace(
                    args,
                    boost::regex("(%innerip%)|(%innerport%)|(%outerip%)|(%outerport%)|(%peerip%)|(%peerport%)|(%secret%)|(%hostid%)|(%peerid%)|(%hostmail%)|(%peermail%)"),
                    plexus::utils::format("(?{1}%s)(?{2}%u)(?{3}%s)(?{4}%u)(?{5}%s)(?{6}%u)(?{7}%llu)(?{8}%s)(?{9}%s)(?{10}%s)(?{11}%s)",
                        bind.address().to_string().c_str(),
                        bind.port(),
                        host.address().to_string().c_str(),
                        host.port(),
                        peer.address().to_string().c_str(),
                        peer.port(),
                        secret,
                        host_info.second.c_str(),
                        peer_info.second.c_str(),
                        host_info.first.c_str(),
                        peer_info.first.c_str()),
                    boost::match_posix | boost::format_all
                    );
            }

            plexus::exec(vm["exec-command"].as<std::string>(), args, vm["exec-pwd"].as<std::string>(), vm["exec-log-file"].as<std::string>());
        };

        do
        {
            try
            {
                if (vm["accept"].as<bool>())
                {
                    plexus::reference peer(mediator->receive_request(peer_info, host_info));
                    plexus::reference host(puncher->punch_hole_to_peer(peer.first, vm["punch-hops"].as<uint16_t>()), plexus::utils::random<uint64_t>());
                    mediator->dispatch_response(host_info, peer_info, host);

                    puncher->await_peer(peer.first, peer.second ^ host.second);
                    execute(host.first, peer.first, peer.second ^ host.second);
                }
                else
                {
                    plexus::reference host(puncher->reflect_endpoint(), plexus::utils::random<uint64_t>());
                    mediator->dispatch_request(host_info, peer_info, host);
                    plexus::reference peer(mediator->receive_response(peer_info, host_info));

                    puncher->reach_peer(peer.first, peer.second ^ host.second);
                    execute(host.first, peer.first, peer.second ^ host.second);
                }
            }
            catch (const std::runtime_error& e)
            {
                if (vm["accept"].as<bool>())
                    std::this_thread::sleep_for(std::chrono::seconds(15));

                _err_ << e.what();
            }
        }
        while (vm["accept"].as<bool>());
    }
    catch(const std::exception& e)
    {
        _ftl_ << e.what();
    }

    return 0;
}
