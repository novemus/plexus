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
        ("mailer.smtps", boost::program_options::value<std::string>()->required(), "smtps server used by plexus postman")
        ("mailer.imaps", boost::program_options::value<std::string>()->required(), "imaps server used by plexus postman")
        ("mailer.login", boost::program_options::value<std::string>()->required(), "login of plexus postman email account")
        ("mailer.passwd", boost::program_options::value<std::string>()->required(), "password of plexus postman email account")
        ("mailer.from", boost::program_options::value<std::string>()->required(), "email address used by local plexus postman")
        ("mailer.to", boost::program_options::value<std::string>()->required(), "email address used by remote plexus postman")
        ("mailer.subj-from", boost::program_options::value<std::string>()->required(), "subject for incoming plexus postman message")
        ("mailer.subj-to", boost::program_options::value<std::string>()->required(), "subject for outgoing plexus postman message")
        ("mailer.cert", boost::program_options::value<std::string>()->default_value(""), "path to X509 certificate for email service")
        ("mailer.key", boost::program_options::value<std::string>()->default_value(""), "path to Private Key for email service")
        ("mailer.ca", boost::program_options::value<std::string>()->default_value(""), "path to email Certification Authority for email service")
        ("mailer.timeout", boost::program_options::value<int64_t>()->default_value(10), "timeout (seconds) to connect to email server")
        ("mailer.smime-peer", boost::program_options::value<std::string>()->default_value(""), "path to plexus X509 certificate for remote host")
        ("mailer.smime-cert", boost::program_options::value<std::string>()->default_value(""), "path to plexus X509 certificate for local host")
        ("mailer.smime-key", boost::program_options::value<std::string>()->default_value(""), "path to plexus Private Key for local host")
        ("mailer.smime-ca", boost::program_options::value<std::string>()->default_value(""), "path to plexus Certification Authority issued plexus certificates")
        ("puncher.stun-ip", boost::program_options::value<std::string>()->required(), "ip of stun server")
        ("puncher.stun-port", boost::program_options::value<uint16_t>()->default_value(3478u), "port of stun server")
        ("puncher.bind-ip", boost::program_options::value<std::string>()->required(), "local ip address from which to punch udp hole")
        ("puncher.bind-port", boost::program_options::value<uint16_t>()->required(), "local port from which to punch udp hole")
        ("puncher.timeout", boost::program_options::value<int64_t>()->default_value(120), "timeout (seconds) to punch hole to a peer")
        ("exec.command", boost::program_options::value<std::string>()->required(), "command to execute after a peer is available")
        ("exec.pwd", boost::program_options::value<std::string>()->default_value(""), "working directory for executable")
        ("exec.log-file", boost::program_options::value<std::string>()->default_value(""), "log file for executable")
        ("app.retry-timeout", boost::program_options::value<int64_t>()->default_value(0), "timeout (seconds) for retrying to connect to a peer")
        ("app.retry-count", boost::program_options::value<int64_t>()->default_value(0), "number of attempts to connect to a peer")
        ("app.log-level", boost::program_options::value<int>()->default_value(plexus::log::debug), "0 - none, 1 - fatal, 2 - error, 3 - warnine, 4 - info, 5 - debug, 6 - trace")
        ("app.log-file", boost::program_options::value<std::string>()->default_value(""), "plexus log file");

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
        plexus::log::set((plexus::log::severity)vm["app.log-level"].as<int>(), vm["app.log-file"].as<std::string>());

        std::shared_ptr<plexus::postman> postman = plexus::create_email_postman(
            vm["mailer.smtps"].as<std::string>(),
            vm["mailer.imaps"].as<std::string>(),
            vm["mailer.login"].as<std::string>(),
            vm["mailer.passwd"].as<std::string>(),
            vm["mailer.from"].as<std::string>(),
            vm["mailer.to"].as<std::string>(),
            vm["mailer.subj-from"].as<std::string>(),
            vm["mailer.subj-to"].as<std::string>(),
            vm["mailer.cert"].as<std::string>(),
            vm["mailer.key"].as<std::string>(),
            vm["mailer.ca"].as<std::string>(),
            vm["mailer.smime-peer"].as<std::string>(),
            vm["mailer.smime-cert"].as<std::string>(),
            vm["mailer.smime-key"].as<std::string>(),
            vm["mailer.smime-ca"].as<std::string>(),
            vm["mailer.timeout"].as<int64_t>()
        );

        int64_t tries = vm["app.retry-count"].as<int64_t>();

        plexus::network::endpoint me;
        plexus::network::endpoint peer;
        do
        {
            try
            {
                std::shared_ptr<plexus::network::puncher> puncher = plexus::network::create_stun_puncher(
                    plexus::network::endpoint(vm["puncher.stun-ip"].as<std::string>(), vm["puncher.stun-port"].as<uint16_t>()),
                    plexus::network::endpoint(vm["puncher.bind-ip"].as<std::string>(), vm["puncher.bind-port"].as<uint16_t>())
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
                    puncher->punch_hole_to_peer(peer, 4000, vm["puncher.timeout"].as<int64_t>() * 1000);

                    std::string args = plexus::utils::format("%s %d %s %d %s %d",
                        vm["puncher.bind-ip"].as<std::string>().c_str(),
                        vm["puncher.bind-port"].as<uint16_t>(),
                        me.first.c_str(),
                        me.second,
                        peer.first.c_str(),
                        peer.second
                        );

                    plexus::exec(
                        vm["exec.command"].as<std::string>(),
                        args,
                        vm["exec.pwd"].as<std::string>(),
                        vm["exec.log-file"].as<std::string>()
                        );
                }
            }
            catch(const plexus::network::timeout_error&)
            {
                _err_ << "timeout";
            }
            std::this_thread::sleep_for(std::chrono::seconds(vm["app.retry-timeout"].as<int64_t>()));
        }
        while (--tries > 0);
    }
    catch(const std::exception& e)
    {
        _ftl_ << e.what();
    }

    return 0;
}
