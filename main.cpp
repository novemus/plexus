#include <string>
#include <iostream>
#include <memory>
#include "tools.h"

int main(int argc, char** argv)
{
    plexus::tools::email_pipe_config config
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
    std::unique_ptr<plexus::tools::pipe> pipe(plexus::tools::create_email_pipe(config));

    pipe->push("hello");
    auto data = pipe->pull();
    while (!data.empty())
    {
        std::cout << data << std::endl;
        data = pipe->pull();
    }
}
