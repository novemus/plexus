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
        ("smtps-server", boost::program_options::value<std::string>()->required(), "smtps server used by plexus postman service")
        ("imaps-server", boost::program_options::value<std::string>()->required(), "imaps server used by plexus postman service")
        ("local-postman", boost::program_options::value<std::string>()->required(), "email address of local plexus postman to send from")
        ("remote-postman", boost::program_options::value<std::string>()->required(), "email address of remote plexus postman to receive from")
        ("email-login", boost::program_options::value<std::string>()->required(), "login of plexus postman email account")
        ("email-password", boost::program_options::value<std::string>()->required(), "password of plexus postman email account")
        ("email-cert", boost::program_options::value<std::string>()->default_value(""), "path to ssl certificate for email service")
        ("email-key", boost::program_options::value<std::string>()->default_value(""), "path to email ssl key for email service")
        ("email-ca", boost::program_options::value<std::string>()->default_value(""), "path to email certification authority for email service")
        ("email-timeout", boost::program_options::value<int64_t>()->default_value(10), "timeout (seconds) to connect to email server")
        ("stun-ip", boost::program_options::value<std::string>()->required(), "ip of stun server")
        ("stun-port", boost::program_options::value<uint16_t>()->default_value(3478u), "port of stun server")
        ("local-ip", boost::program_options::value<std::string>()->required(), "local ip address to bind plexus")
        ("local-port", boost::program_options::value<uint16_t>()->required(), "local port address to bind plexus")
        ("handshake-timeout", boost::program_options::value<int64_t>()->default_value(120), "timeout (seconds) to handshake with a peer")
        ("retry-timeout", boost::program_options::value<int64_t>()->default_value(0), "timeout (seconds) to retry to connect with a peer")
        ("retry-count", boost::program_options::value<int64_t>()->default_value(0), "number of attempts to connect with a peer")
        ("exec-command", boost::program_options::value<std::string>()->required(), "command to execute after a peer is available")
        ("exec-pwd", boost::program_options::value<std::string>()->default_value(""), "working directory for executable")
        ("exec-log", boost::program_options::value<std::string>()->default_value(""), "log file for executable")
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

        std::shared_ptr<plexus::postman> postman = plexus::create_email_postman(
            vm["smtps-server"].as<std::string>(),
            vm["imaps-server"].as<std::string>(),
            vm["local-postman"].as<std::string>(),
            vm["remote-postman"].as<std::string>(),
            vm["email-login"].as<std::string>(),
            vm["email-password"].as<std::string>(),
            vm["email-cert"].as<std::string>(),
            vm["email-key"].as<std::string>(),
            vm["email-ca"].as<std::string>(),
            vm["email-timeout"].as<int64_t>()
        );

        int64_t tries = vm["retry-count"].as<int64_t>();

        plexus::network::endpoint me;
        plexus::network::endpoint peer;
        do
        {
            try
            {
                std::shared_ptr<plexus::network::puncher> puncher = plexus::network::create_stun_puncher(
                    vm["stun-ip"].as<std::string>(),
                    vm["stun-port"].as<uint16_t>(),
                    vm["local-ip"].as<std::string>(),
                    vm["local-port"].as<uint16_t>()
                    );

                plexus::network::traverse state = puncher->explore_network();
                if (state.mapping != plexus::network::independent)
                {
                    _err_ << "network configuration does not allow to establish peer connection";
                    return 0;
                }

                plexus::network::endpoint endpoint = puncher->punch_udp_hole();
                if (me != endpoint)
                {
                    me = endpoint;
                    std::string request = "READY " + endpoint.first + " " + std::to_string(endpoint.second);
                    postman->send_message(request);
                }

                std::string message;
                do
                {
                    message = postman->receive_message();
                    if (!message.empty())
                    {
                        std::smatch match;
                        if (std::regex_search(message, match, std::regex("^READY\\s+(\\S+)\\s+(\\d+)$")))
                        {
                            peer = std::make_pair(match[1].str(), boost::lexical_cast<uint16_t>(match[2].str()));
                        }
                    }
                } 
                while (!message.empty());

                if (!peer.first.empty())
                {
                    puncher->punch_hole_to_peer(peer, 4000, vm["handshake-timeout"].as<int64_t>() * 1000);

                    std::string args = plexus::utils::format("%s %d %s %d %s %d",
                        vm["local-ip"].as<std::string>().c_str(),
                        vm["local-port"].as<uint16_t>(),
                        me.first.c_str(),
                        me.second,
                        peer.first.c_str(),
                        peer.second
                        );

                    plexus::exec(
                        vm["exec-command"].as<std::string>(),
                        args,
                        vm["exec-pwd"].as<std::string>(),
                        vm["exec-log"].as<std::string>()
                        );
                }
            }
            catch(const plexus::network::timeout_error&)
            {
                _err_ << "timeout";
            }
            std::this_thread::sleep_for(std::chrono::seconds(vm["retry-timeout"].as<int64_t>()));
        }
        while (--tries > 0);
    }
    catch(const std::exception& e)
    {
        _ftl_ << e.what();
    }

    return 0;
}
