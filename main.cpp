#include <string>
#include <iostream>
#include <memory>
#include "tools.h"
#include "network.h"

int main(int argc, char** argv)
{
    try
    {
        plexus::features::email_pipe_config config
        {
            "smtp.yandex.ru:465",
            "imap.yandex.ru:993",
            "sergey-nine@yandex.ru",
            "*********************",
            "",
            "",
            "sergey-nine@yandex.ru",
            "sergey-nine@yandex.ru",
            10
        };
        std::unique_ptr<plexus::features::pipe> pipe(plexus::features::create_email_pipe(config));

        pipe->push("hello");
        auto data = pipe->pull();
        while (!data.empty())
        {
            std::cout << data << std::endl;
            data = pipe->pull();
        }

        std::unique_ptr<plexus::network::channel> udp(plexus::network::create_udp_channel("127.0.0.1", 5000, "127.0.0.1", 5001, 30));
        udp->open();
        char buffer[1024];
        int size = udp->read(buffer, 1024);
        std::cout << buffer << std::endl;

        udp->write(buffer, size);
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
    }
    

}
