#pragma once

#include <string>
#include <vector>
#include <memory>
#include <future>

namespace plexus { namespace network
{
    struct channel
    {
        virtual ~channel() {}
        virtual void connect() noexcept(false) = 0;
        virtual void shutdown() noexcept(false) = 0;
        virtual size_t read(unsigned char* buffer, size_t len) noexcept(false) = 0;
        virtual size_t write(const unsigned char* buffer, size_t len) noexcept(false) = 0;
    };

    std::shared_ptr<channel> create_ssl_channel(const std::string& url, const std::string& cert = "", const std::string& key = "", long timeout_sec = 10);

    struct udp_client
    {
        struct transfer
        {
             std::string host;
             std::string service;
             std::vector<unsigned char> buffer;

             transfer(size_t b) : buffer(b, 0) {}
             transfer(const std::string& h, const std::string& s, size_t b = 0) : host(h), service(s), buffer(b, 0) {}
             transfer(const std::string& h, const std::string& s, const std::initializer_list<unsigned char>& b) : host(h), service(s), buffer(b) {}
        };
        typedef std::shared_ptr<transfer> transfer_ptr;

        virtual ~udp_client() {}
        virtual std::future<size_t> send(transfer_ptr data, long timeout_ms = 2000) noexcept(false) = 0;
        virtual std::future<size_t> receive(transfer_ptr data, long timeout_ms = 2000) noexcept(false) = 0;
    };

    std::shared_ptr<udp_client> create_udp_client(const std::string& address = "127.0.0.1", unsigned short port = 5000);
}}
