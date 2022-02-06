#include <string>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <memory>
#include <utility>
#include "features.h"
#include "utils.h"
#include "network.h"
#include "log.h"

int main(int argc, char** argv)
{
    try
    {
        plexus::log::set(plexus::log::debug);

        // _ftl_ << "fatal" << " message " << plexus::log::fatal;
        // _err_ << "error" << " message " << plexus::log::error;
        // _wrn_ << "warning" << " message " << plexus::log::warning;
        // _inf_ << "info" << " message " << plexus::log::info;
        // _dbg_ << "debug" << " message " << plexus::log::debug;
        // _trc_ << "trace" << " message " << plexus::log::trace;

        // std::unique_ptr<plexus::postman> postman(plexus::create_email_postman(
        //     "smtp.yandex.ru:465",
        //     "imap.yandex.ru:993",
        //     "sergey-nine@yandex.ru",
        //     "sergey-nine@yandex.ru",
        //     "sergey-nine@yandex.ru",
        //     "",
        //     "",
        //     "",
        //     10
        // ));

        //postman->send_message("hello");
        // auto data = postman->receive_message();
        // while (!data.empty())
        // {
        //     _inf_ << data;
        //     data = postman->receive_message();
        // }

        // std::shared_ptr<plexus::network::udp> client = plexus::network::create_udp_client("192.168.1.104", 5000);

        // auto send = std::make_shared<plexus::network::udp::transfer>("192.168.1.104", "5000", std::initializer_list<unsigned char>{ 
        //     0x00, 0x01, 0x00, 0x08, 0x21, 0x12, 0xa4, 0x42, 0xa6, 0x8b, 0x57, 0x5f, 0x77, 0xb8, 0x0f, 0x1d, 0x09, 0x9f, 0x65, 0x7f, 0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00 });
        // auto recv = std::make_shared<plexus::network::udp::transfer>(1024);

        // client->send(send);
        // client->receive(recv);

        // _inf_ << send->host << ":" << send->service << " <- " << client->send(send);
        // _inf_ << recv->host << ":" << recv->service << " -> " << client->receive(recv);

        //plexus::exec("ls", "-l", "/home/nine", "out.log");

        std::shared_ptr<plexus::network::puncher> stun = plexus::network::create_stun_puncher("216.93.246.18", "192.168.0.105", 5000u);
        stun->explore_network();
        // stun->punch_udp_hole();

        auto t1 = std::async(std::launch::async, [stun]() {
            stun->punch_hole_to_peer(std::make_pair("192.168.0.105", 5002u));
        });

        std::shared_ptr<plexus::network::puncher> peer(plexus::network::create_stun_puncher("77.72.169.211", "192.168.0.105", 5002u));
        peer->explore_network();
        // peer->punch_udp_hole();

        auto t2 = std::async(std::launch::async, [peer]() {
            peer->punch_hole_to_peer(std::make_pair("192.168.0.105", 5000u));
        });

        t1.get();
        t2.get();
    }
    catch(const std::exception& e)
    {
        _ftl_ << e.what();
    }

    return 0;
}
