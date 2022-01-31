#include <string>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <memory>
#include "features.h"
#include "network.h"

std::string stringify(uint8_t* data, size_t len)
{
    std::stringstream ss;
    ss << std::hex;
    for (size_t i = 0; i < len; ++i)
        ss << std::setw(2) << std::setfill('0') << (int)data[i];
    return ss.str();
}

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
        //     std::cout << data << std::endl;
        //     data = pipe->pull();
        // }

        // std::shared_ptr<plexus::network::udp_client> client = plexus::network::create_udp_client("192.168.1.104", 5000);

        // auto send = std::make_shared<plexus::network::udp_client::transfer>("192.168.1.104", "5000", std::initializer_list<unsigned char>{ 
        //     0x00, 0x01, 0x00, 0x08, 0x21, 0x12, 0xa4, 0x42, 0xa6, 0x8b, 0x57, 0x5f, 0x77, 0xb8, 0x0f, 0x1d, 0x09, 0x9f, 0x65, 0x7f, 0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00 });
        // auto recv = std::make_shared<plexus::network::udp_client::transfer>(1024);

        // auto s = client->send(send);
        // auto r = client->receive(recv);

        // auto sent = s.get();
        // std::cout << send->host << ":" << send->service << " <- " << stringify(send->buffer.data(), sent) << std::endl;
        
        // auto received = r.get();
        // std::cout << recv->host << ":" << recv->service << " -> " << stringify(recv->buffer.data(), received) << std::endl;

        std::shared_ptr<plexus::network::stun_client> stun(plexus::network::create_stun_client("216.93.246.18", "10.8.0.3", 5000u));
        stun->explore_network();
        plexus::network::endpoint endpoint = stun->punch_udp_hole();
        std::cout << endpoint.first << ":" << endpoint.second << std::endl;
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}
