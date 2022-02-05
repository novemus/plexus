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
        // plexus::network::email_pipe_config config
        // {
        //     "smtp.yandex.ru:465",
        //     "imap.yandex.ru:993",
        //     "sergey-nine@yandex.ru",
        //     "",
        //     "",
        //     "",
        //     "sergey-nine@yandex.ru",
        //     "sergey-nine@yandex.ru",
        //     10
        // };
        // std::unique_ptr<plexus::network::pipe> pipe(plexus::network::create_email_pipe(config));

        // pipe->push("hello");
        // auto data = pipe->pull();
        // while (!data.empty())
        // {
        //     _inf_ << data;
        //     data = pipe->pull();
        // }

        // std::shared_ptr<plexus::network::udp_client> client = plexus::network::create_udp_client("192.168.1.104", 5000);

        // auto send = std::make_shared<plexus::network::udp_client::transfer>("192.168.1.104", "5000", std::initializer_list<unsigned char>{ 
        //     0x00, 0x01, 0x00, 0x08, 0x21, 0x12, 0xa4, 0x42, 0xa6, 0x8b, 0x57, 0x5f, 0x77, 0xb8, 0x0f, 0x1d, 0x09, 0x9f, 0x65, 0x7f, 0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00 });
        // auto recv = std::make_shared<plexus::network::udp_client::transfer>(1024);

        // auto s = client->send(send);
        // auto r = client->receive(recv);

        // auto sent = s.get();
        // _inf_ << send->host << ":" << send->service << " <- " << stringify(send->buffer.data(), sent);
        
        // auto received = r.get();
        // _inf_ << recv->host << ":" << recv->service << " -> " << stringify(recv->buffer.data(), received);

        plexus::log::set(plexus::log::trace);

        // _ftl_ << "fatal" << " message " << plexus::log::fatal;
        // _err_ << "error" << " message " << plexus::log::error;
        // _wrn_ << "warning" << " message " << plexus::log::warning;
        // _inf_ << "info" << " message " << plexus::log::info;
        // _dbg_ << "debug" << " message " << plexus::log::debug;
        // _trc_ << "trace" << " message " << plexus::log::trace;

        //plexus::exec("ls", "-l", "/home/nine", "out.log");

        std::shared_ptr<plexus::network::udp_puncher> stun(plexus::network::create_udp_puncher("216.93.246.18", "192.168.0.105", 5000u));
        stun->punch_udp_hole();
        std::shared_ptr<plexus::network::udp_puncher> peer(plexus::network::create_udp_puncher("77.72.169.211", "192.168.0.105", 5002u));
        peer->punch_udp_hole();

        auto t1 = std::async(std::launch::async, [stun]() {
            stun->meet_peer(std::make_pair("192.168.0.105", 5002u));
            stun->close();
        });

        auto t2 = std::async(std::launch::async, [peer]() {
            peer->meet_peer(std::make_pair("192.168.0.105", 5000u));
            peer->close();
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
