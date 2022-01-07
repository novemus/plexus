#include <string>
#include <iostream>
#include <memory>
#include "pipe.h"

int main(int argc, char** argv)
{
    plexus::email_pipe::config config
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
    std::unique_ptr<plexus::pipe> pipe(plexus::email_pipe::open(config));

    pipe->push("hello");
    auto data = pipe->pull();
    while (!data.empty())
    {
        std::cout << data << std::endl;
        data = pipe->pull();
    }
}
