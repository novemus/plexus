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
#include <filesystem>
#include <stdexcept>
#include <logger.h>
#include <boost/program_options.hpp>
#include <boost/regex.hpp>

constexpr int success = 0;
constexpr int common_error = -1;
constexpr int bad_options = -2;
constexpr int bad_network = -3;

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

enum usage
{
    to_listen,
    to_accept,
    to_invite
};

std::istream& operator>>(std::istream& in, usage& mode)
{
    std::string str;
    in >> str;

    if (str == "listen" || str == "LISTEN" || str == "0")
        mode = usage::to_listen;
    else if (str == "accept" || str == "ACCEPT" || str == "1")
        mode = usage::to_accept;
    else
        mode = usage::to_invite;

    return in;
}

std::ostream& operator<<(std::ostream& out, usage mode)
{
    switch(mode)
    {
        case usage::to_listen:
            return out << "LISTEN";
        case usage::to_accept:
            return out << "ACCEPT";
        default:
            return out << "INVITE";
    }
    return out;
}

int listen(const boost::program_options::variables_map& vm)
{
    static const char* args_pattern = "--email-smtps=%s:%u --email-imaps=%s:%u --email-login=%s --email-passwd=%s --email-cert=%s --email-ca=%s --email-key=%s"
                                      "--mode=accept --app-id=%s --app-repo=%s --host-email=%s --host-id=%s --peer-email=%s --peer-id=%s"
                                      "--stun-server=%s:%u --stun-client=%s:%u --punch-hops=%u --exec-command=%s --exec-args=%s"
                                      "--exec-pwd=%s --exec-log-file=%s --log-level=%u --log-file=%s";
    try
    {
        auto imaps = vm["email-imaps"].as<imap_server_endpoint>();
        auto smtps = vm["email-smtps"].as<smtp_server_endpoint>();
        auto login = vm["email-login"].as<std::string>();
        auto passwd = vm["email-passwd"].as<std::string>();
        auto cert = vm["email-cert"].as<std::string>();
        auto key = vm["email-key"].as<std::string>();
        auto ca = vm["email-ca"].as<std::string>();
        auto app = vm["app-id"].as<std::string>();
        auto repo = vm["app-repo"].as<std::string>();
        auto stuns = vm["stun-server"].as<stun_server_endpoint>();
        auto stunc = vm["stun-client"].as<stun_client_endpoint>();

        auto listener = plexus::create_email_listener(imaps, login, passwd, cert, key, ca, app, repo);

        do
        {
            listener->listen();

            auto host = listener->host();
            auto peer = listener->peer();

            _inf_ << "coupling peer=" << peer.first << "/" << peer.second << " and host=" << host.first << "/" << host.second;

            std::string args = plexus::utils::format(args_pattern,
                smtps.address().to_string().c_str(), smtps.port(),
                imaps.address().to_string().c_str(), imaps.port(),
                login.c_str(), passwd.c_str(),
                cert.c_str(), ca.c_str(), key.c_str(),
                app.c_str(), repo.c_str(),
                host.first.c_str(), host.second.c_str(),
                peer.first.c_str(), peer.second.c_str(),
                stuns.address().to_string().c_str(), stuns.port(),
                stunc.address().to_string().c_str(), stunc.port(),
                vm["punch-hops"].as<uint16_t>(),
                vm["exec-command"].as<std::string>().c_str(),
                vm["exec-args"].as<std::string>().c_str(),
                vm["exec-pwd"].as<std::string>().c_str(),
                vm["exec-log-file"].as<std::string>().c_str(),
                vm["log-level"].as<wormhole::log::severity>(),
                vm["log-file"].as<std::string>().c_str()
                );

            plexus::exec("plexus", args, std::filesystem::current_path().generic_u8string(), vm["log-file"].as<std::string>(), false);
        }
        while (true);
    }
    catch(const std::exception& e)
    {
        _ftl_ << e.what();
        return common_error;
    }

    return success;
}

int couple(const boost::program_options::variables_map& vm)
{
    try
    {
        auto host_info = std::make_pair(plexus::utils::get_email_address(vm["host-email"].as<std::string>()), vm["host-id"].as<std::string>());
        auto peer_info = std::make_pair(plexus::utils::get_email_address(vm["peer-email"].as<std::string>()), vm["peer-id"].as<std::string>());

        boost::asio::ip::udp::endpoint stun = vm["stun-server"].as<stun_server_endpoint>();
        boost::asio::ip::udp::endpoint bind = vm["stun-client"].as<stun_client_endpoint>();

        auto puncher = plexus::create_nat_puncher(stun, bind);

        _dbg_ << "stun server: " << stun;
        _dbg_ << "stun client: " << bind;

        plexus::traverse state = puncher->explore_network();
        if (state.mapping != plexus::independent)
        {
            _err_ << "network configuration does not allow to establish peer connection";
            return bad_network;
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
            vm["app-repo"].as<std::string>(),
            host_info,
            peer_info
            );

        auto execute = [&](const boost::asio::ip::udp::endpoint& host, const boost::asio::ip::udp::endpoint& peer, uint64_t secret)
        {
            auto format = [&](const std::string& line)
            {
                return boost::regex_replace(line,
                    boost::regex("(%innerip%)|(%innerport%)|(%outerip%)|(%outerport%)|(%peerip%)|(%peerport%)|(%secret%)|(%hostid%)|(%peerid%)|(%hostemail%)|(%peeremail%)"),
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
            };

            plexus::exec(format(vm["exec-command"].as<std::string>()), format(vm["exec-args"].as<std::string>()), format(vm["exec-pwd"].as<std::string>()), format(vm["exec-log-file"].as<std::string>()));
        };

        if (vm["usage"].as<usage>() == usage::to_accept)
        {
            plexus::reference peer(mediator->pull_request());
            plexus::reference host(puncher->punch_hole_to_peer(peer.first, vm["punch-hops"].as<uint16_t>()), plexus::utils::random<uint64_t>());
            mediator->push_response(host);

            puncher->await_peer(peer.first, peer.second ^ host.second);
            execute(host.first, peer.first, peer.second ^ host.second);
        }
        else
        {
            plexus::reference host(puncher->reflect_endpoint(), plexus::utils::random<uint64_t>());
            mediator->push_request(host);
            plexus::reference peer(mediator->pull_response());

            puncher->reach_peer(peer.first, peer.second ^ host.second);
            execute(host.first, peer.first, peer.second ^ host.second);
        }
    }
    catch(const std::exception& e)
    {
        _ftl_ << e.what();
        return common_error;
    }

    return success;
}

int main(int argc, char** argv)
{
    boost::program_options::options_description desc("plexus options");
    desc.add_options()
        ("help", "produce help message")
        ("usage", boost::program_options::value<usage>()->required(), "util usage: <listen|accept|invite>")
        ("app-id", boost::program_options::value<std::string>()->required(), "identifier of the application")
        ("app-repo", boost::program_options::value<std::string>()->default_value(""), "path to application repository")
        ("host-email", boost::program_options::value<std::string>(), "email address used by the host")
        ("host-id", boost::program_options::value<std::string>(), "unique plexus identifier of the host")
        ("peer-email", boost::program_options::value<std::string>(), "email address used by the peer")
        ("peer-id", boost::program_options::value<std::string>(), "unique plexus identifier of the peer")
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
        ("exec-args", boost::program_options::value<std::string>()->default_value(""), "arguments for the command executed after punching the NAT, allowed wildcards: %innerip%, %innerport%, %outerip%, %outerport%, %peerip%, %peerport%, %secret%, %hostid%, %peerid%, %hostemail%, %peeremail%")
        ("exec-pwd", boost::program_options::value<std::string>()->default_value(""), "working directory for executable, the above wildcards are allowed")
        ("exec-log-file", boost::program_options::value<std::string>()->default_value(""), "log file for executable, the above wildcards are allowed")
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
            return success;
        }

        if(vm.count("config"))
            boost::program_options::store(boost::program_options::parse_config_file<char>(vm["config"].as<std::string>().c_str(), desc), vm);

        if (vm["usage"].as<usage>() != usage::to_listen)
        {
            if (!vm.count("host-email") || !vm.count("host-id") || !vm.count("peer-email") || !vm.count("peer-id"))
                throw std::runtime_error("the following options are required: '--host-email', '--host-id', '--peer-email', '--peer-id'");
        }
        else
        {
            if (vm.count("host-email") || vm.count("host-id") || vm.count("peer-email") || vm.count("peer-email"))
                throw std::runtime_error("the following options are forbidden: '--host-email', '--host-id', '--peer-email', '--peer-id'");

            if (vm["app-repo"].as<std::string>().empty())
                throw std::runtime_error("the 'app-repo' option is required");
        }
        boost::program_options::notify(vm);
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
        std::cout << desc;
        return bad_options;
    }

    wormhole::log::set(vm["log-level"].as<wormhole::log::severity>(), false, vm["log-file"].as<std::string>());

    return vm["usage"].as<usage>() == usage::to_listen ? listen(vm) : couple(vm);
}
