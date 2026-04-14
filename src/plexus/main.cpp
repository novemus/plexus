/*
 * Copyright (c) 2022 Novemus Band. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 */

#include <plexus/features.h>
#include <plexus/plexus.h>
#include <plexus/utils.h>
#include <wormhole/logger.h>
#include <regex>
#include <unordered_map>
#include <boost/program_options.hpp>

using namespace plexus;

constexpr char stun_default_port[] = "3478";
constexpr char bind_default_port[] = "0";
constexpr char smtp_default_port[] = "smtps";
constexpr char imap_default_port[] = "imaps";

int main(int argc, char** argv)
{
    boost::program_options::options_description desc("plexus options", 200, 100);
    desc.add_options()
        ("help", "produce help message")
        ("accept", boost::program_options::bool_switch(), "accept or invite peer to initiate connection")
        ("app-name", boost::program_options::value<std::string>()->required(), "name of the application")
        ("app-repo", boost::program_options::value<std::string>()->default_value(""), "path to the application repository")
        ("app-qos", boost::program_options::value<criteria>()->default_value(criteria()), "application protocol and connection schema: <udp|tcp|ssl|any>:<client|server|mutual|either>")
        ("host-id", boost::program_options::value<identity>()->default_value(identity()), "identifier of the host: <email/pin>")
        ("peer-id", boost::program_options::value<identity>()->default_value(identity()), "identifier of the peer: <email/pin>")
        ("udp-bind", boost::program_options::value<std::string>()->default_value("0.0.0.0:0"), "udp endpoint to bind the application")
        ("tcp-bind", boost::program_options::value<std::string>()->default_value("0.0.0.0:0"), "tcp endpoint to bind the application")
        ("udp-stun", boost::program_options::value<std::string>()->default_value("stunserver2025.stunprotocol.org"), "udp STUN server")
        ("tcp-stun", boost::program_options::value<std::string>()->default_value("stunserver2025.stunprotocol.org"), "tcp STUN server")
        ("punch-hops", boost::program_options::value<uint16_t>()->default_value(7), "time-to-live parameter for the NAT punching packet")
        ("dht-bootstrap", boost::program_options::value<std::string>()->default_value("bootstrap.jami.net"), "url of the bootstrap DHT service")
        ("dht-port", boost::program_options::value<uint16_t>()->default_value(0), "local port to bind the DHT node")
        ("dht-network", boost::program_options::value<uint32_t>()->default_value(0), "DHT network id")
        ("email-smtps", boost::program_options::value<std::string>(), "smtps server used for the email rendezvous")
        ("email-imaps", boost::program_options::value<std::string>(), "imaps server used for the email rendezvous")
        ("email-login", boost::program_options::value<std::string>(), "login of the email account")
        ("email-password", boost::program_options::value<std::string>(), "password of the email account")
        ("email-cert", boost::program_options::value<std::string>()->default_value(""), "path to the X509 certificate of the email client")
        ("email-key", boost::program_options::value<std::string>()->default_value(""), "path to the Private Key of the email client")
        ("email-ca", boost::program_options::value<std::string>()->default_value(""), "path to the email Certification Authority")
        ("exec-cmd", boost::program_options::value<std::string>()->required(), "command executed after the host is ready to communicate with the peer")
        ("exec-args", boost::program_options::value<std::string>()->default_value("%inner% %outer% %alien% %qos%"), "list of arguments for the command, allowed wildcards: %inner%, %outer%, %alien%, %qos%, %hostid%, %peerid%")
        ("exec-env", boost::program_options::value<std::string>()->default_value(""), "KEY=VALUE list of extra environment for the command, allowed wildcards: %secret%, %hostcert%, %hostkey%, %peercert%")
        ("exec-pwd", boost::program_options::value<std::string>()->default_value(""), "working directory for the command, allowed wildcards: %hostid%, %peerid%")
        ("exec-log", boost::program_options::value<std::string>()->default_value(""), "command log file, allowed wildcards: %hostid%, %peerid%")
        ("log-level", boost::program_options::value<wormhole::log::severity>()->default_value(wormhole::log::info), "log level: <fatal|error|warning|info|debug|trace>")
        ("log-file", boost::program_options::value<std::string>()->default_value(""), "plexus log file, allowed %p (process id) wildcard")
        ("config", boost::program_options::value<std::string>(), "path to the INI-like configuration file");

    boost::program_options::variables_map vm;
    try
    {
        boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), vm);
        if(vm.count("help"))
        {
            std::cout << desc << std::endl;
            return -1;
        }

        if(vm.count("config"))
            boost::program_options::store(boost::program_options::parse_config_file<char>(vm["config"].as<std::string>().c_str(), desc), vm);

        auto count = vm.count("email-smtps") + vm.count("email-imaps") + vm.count("email-login") + vm.count("email-password");
        if(count > 0 && count != 4)
        {
            std::cout << "to use email service as a rendezvous, specify at least the 'email-smtps', 'email-imaps', 'email-login' and 'email-password' arguments" << std::endl;
            return -1;
        }

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

        auto launch = [&](const identity& host, const identity& peer, const contract& info)
        {
            static constexpr const char* HOSTID = "%hostid%";
            static constexpr const char* PEERID = "%peerid%";
            static constexpr const char* INNER = "%inner%";
            static constexpr const char* OUTER = "%outer%";
            static constexpr const char* ALIEN = "%alien%";
            static constexpr const char* QOS = "%qos%";
            static constexpr const char* SECRET = "%secret%";
            static constexpr const char* HOSTCERT = "%hostcert%";
            static constexpr const char* HOSTKEY = "%hostkey%";
            static constexpr const char* PEERCERT = "%peercert%";

            auto replace = [&](const std::string& text, std::initializer_list<std::string> wildcards)
            {
                auto check_path = [](const std::string& path)
                {
                    return std::filesystem::exists(path) ? path : "";
                };

                std::string pattern;
                std::string result;
                std::unordered_map<std::string, std::string> replacements;

                for (const auto& token : wildcards)
                {
                    if (!pattern.empty())
                        pattern += "|";

                    pattern += token;

                    if (token == HOSTID)
                        replacements[token] = host.owner + "/" + host.pin;
                    else if (token == PEERID)
                        replacements[token] = peer.owner + "/" + peer.pin;
                    else if (token == INNER)
                        replacements[token] = endpoint::to_string(info.inner);
                    else if (token == OUTER)
                        replacements[token] = endpoint::to_string(info.outer);
                    else if (token == ALIEN)
                        replacements[token] = endpoint::to_string(info.alien);
                    else if (token == QOS)
                        replacements[token] = criteria::to_string(info.qos);
                    else if (token == SECRET)
                        replacements[token] = std::to_string(info.secret);
                    else if (token == HOSTCERT)
                        replacements[token] = check_path(vm["app-repo"].as<std::string>() + "/" + host.owner + "/" + host.pin + "/cert.crt");
                    else if (token == HOSTKEY)
                        replacements[token] = check_path(vm["app-repo"].as<std::string>() + "/" + host.owner + "/" + host.pin + "/private.key");
                    else if (token == PEERCERT)
                        replacements[token] = check_path(vm["app-repo"].as<std::string>() + "/" + peer.owner + "/" + peer.pin + "/cert.crt");
                }

                size_t tail = 0;
                std::regex regex(pattern);

                auto iter = std::sregex_iterator(text.begin(), text.end(), regex);
                while (iter != std::sregex_iterator())
                {
                    std::smatch match = *iter;
                    result.append(text, tail, match.position() - tail);
                    result.append(replacements.at(match.str()));
                    tail = match.position() + match.length();
                    ++iter;
                }

                result.append(text, tail, text.length() - tail);

                return result;
            };

            plexus::exec(
                vm["exec-cmd"].as<std::string>(),
                replace(vm["exec-args"].as<std::string>(), { HOSTID, PEERID, INNER, OUTER, ALIEN, QOS }),
                replace(vm["exec-pwd"].as<std::string>(), { HOSTID, PEERID }),
                replace(vm["exec-log"].as<std::string>(), { HOSTID, PEERID }),
                replace(vm["exec-env"].as<std::string>(), { SECRET, HOSTCERT, HOSTKEY, PEERCERT })
                );
        };

        location bind {
            utils::resolve_some<boost::asio::ip::udp>(vm["udp-bind"].as<std::string>(), bind_default_port),
            utils::resolve_some<boost::asio::ip::tcp>(vm["tcp-bind"].as<std::string>(), bind_default_port)
        };

        location stun {
            utils::resolve_same<boost::asio::ip::udp>(bind.udp.address, vm["udp-stun"].as<std::string>(), stun_default_port),
            utils::resolve_same<boost::asio::ip::tcp>(bind.tcp.address, vm["tcp-stun"].as<std::string>(), stun_default_port)
        };

        options config = {
            vm["app-name"].as<std::string>(),
            vm["app-repo"].as<std::string>(),
            bind,
            stun,
            vm["punch-hops"].as<uint16_t>(),
            vm["app-qos"].as<criteria>(),
            vm.count("email-smtps")
                ? rendezvous {
                    emailer {
                        utils::resolve_some<boost::asio::ip::tcp>(vm["email-smtps"].as<std::string>(), smtp_default_port),
                        utils::resolve_some<boost::asio::ip::tcp>(vm["email-imaps"].as<std::string>(), imap_default_port),
                        vm["email-login"].as<std::string>(),
                        vm["email-password"].as<std::string>(),
                        vm["email-cert"].as<std::string>(),
                        vm["email-key"].as<std::string>(),
                        vm["email-ca"].as<std::string>() 
                    }}
                : rendezvous {
                    dhtnode {
                        vm["dht-bootstrap"].as<std::string>(),
                        vm["dht-port"].as<uint16_t>(),
                        vm["dht-network"].as<uint32_t>() 
                    }}
        };

        boost::asio::io_context io;
        vm["accept"].as<bool>()
            ? plexus::spawn_accept(io, config, vm["host-id"].as<identity>(), vm["peer-id"].as<identity>(), launch)
            : plexus::spawn_invite(io, config, vm["host-id"].as<identity>(), vm["peer-id"].as<identity>(), launch);
        io.run();
    }
    catch(const std::exception& e)
    {
        _ftl_ << e.what();
        return -1;
    }

    return 0;
}
