#pragma once

#include <string>
#include <vector>
#include <memory>
#include <future>

namespace plexus { namespace network
{
    struct ssl
    {
        virtual ~ssl() {}
        virtual void connect() noexcept(false) = 0;
        virtual void shutdown() noexcept(false) = 0;
        virtual size_t read(uint8_t* buffer, size_t len) noexcept(false) = 0;
        virtual size_t write(const uint8_t* buffer, size_t len) noexcept(false) = 0;
    };

    std::shared_ptr<ssl> create_ssl_client(const std::string& url, const std::string& cert = "", const std::string& key = "", const std::string& ca = "", int64_t timeout_sec = 10);

    typedef std::pair<std::string, uint16_t> endpoint;

    struct udp
    {
        struct transfer
        {
             endpoint remote;
             std::vector<uint8_t> buffer;

             transfer(size_t b) : buffer(b, 0) {}
             transfer(const endpoint& r, size_t b = 0) : remote(r), buffer(b, 0) {}
             transfer(const endpoint& r, const std::vector<uint8_t>& b) : remote(r), buffer(b) {}
             transfer(const endpoint& r, std::initializer_list<uint8_t> b) : remote(r), buffer(b) {}
        };

        virtual ~udp() {}
        virtual size_t send(std::shared_ptr<transfer> data, int64_t timeout_ms = 1600) noexcept(false) = 0;
        virtual size_t receive(std::shared_ptr<transfer> data, int64_t timeout_ms = 1600) noexcept(false) = 0;
    };

    std::shared_ptr<udp> create_udp_channel(const std::string& address = "127.0.0.1", uint16_t port = 5000);
}}
