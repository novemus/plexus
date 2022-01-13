#pragma once

#include <string>

namespace plexus { namespace network
{
    struct channel
    {
        virtual ~channel() {}
        virtual void open() noexcept(false) = 0;
        virtual void close() noexcept(false) = 0;
        virtual int read(char* buffer, int len) noexcept(false) = 0;
        virtual int write(const char* buffer, int len) noexcept(false) = 0;
    };

    channel* create_ssl_channel(const std::string& url, const std::string& cert = "", const std::string& key = "", long timeout = 10);
    channel* create_udp_channel(const std::string& dst_ip, unsigned short dst_port, const std::string& src_ip = "127.0.0.1", unsigned short src_port = 5000, long timeout = 10);
}}
