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
        plexus::features::email_pipe_config config
        {
            "smtp.yandex.ru:465",
            "imap.yandex.ru:993",
            "sergey-nine@yandex.ru",
            "",
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

        std::shared_ptr<plexus::features::network_traverse> travers(plexus::features::create_network_traverse(
            "216.93.246.18", "10.8.0.4", 5000u
            ));
        travers->explore_firewall();
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}
