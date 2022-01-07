#pragma once

#include <string>

namespace plexus
{
    struct pipe
    {
        virtual ~pipe() {}
        virtual void push(const std::string& data) noexcept(false) = 0;
        virtual std::string pull() noexcept(false) = 0;
    };

    namespace email_pipe
    {
        struct config
        {
            std::string smtp;
            std::string imap;
            std::string login;
            std::string password;
            std::string certificate;
            std::string key;
            std::string frontend;
            std::string backend;
            long timeout;
        };

        pipe* open(const config& config);
    }
}
