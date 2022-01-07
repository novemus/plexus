#pragma once

#include <string>

namespace plexus
{
    struct ssl_channel
    {
        virtual ~ssl_channel() {}

        virtual void connect() noexcept(false) = 0;
        virtual int read(char* buffer, int len) noexcept(false) = 0;
        virtual int write(const char* buffer, int len) noexcept(false) = 0;

        static ssl_channel* open(const std::string& url, const std::string& cert = "", const std::string& key = "", long timeout = 10);
    };
}
