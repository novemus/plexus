#pragma once

#include <string>
#include <vector>
#include <memory>
#include <future>

namespace plexus { namespace network
{
    struct timeout_error : public std::runtime_error { timeout_error() : std::runtime_error("timeout") {} };

    struct channel
    {
        virtual ~channel() {}
        virtual void connect() noexcept(false) = 0;
        virtual void shutdown() noexcept(false) = 0;
        virtual size_t read(uint8_t* buffer, size_t len) noexcept(false) = 0;
        virtual size_t write(const uint8_t* buffer, size_t len) noexcept(false) = 0;
    };

    std::shared_ptr<channel> create_ssl_channel(const std::string& url, const std::string& cert = "", const std::string& key = "", int64_t timeout_sec = 10);

    struct udp_client
    {
        struct transfer
        {
             std::string host;
             std::string service;
             std::vector<uint8_t> buffer;

             transfer(size_t b) : buffer(b, 0) {}
             transfer(const std::string& h, const std::string& s, size_t b = 0) : host(h), service(s), buffer(b, 0) {}
             transfer(const std::string& h, const std::string& s, std::initializer_list<uint8_t> b) : host(h), service(s), buffer(b) {}
        };
        typedef std::shared_ptr<transfer> transfer_ptr;

        virtual ~udp_client() {}
        virtual std::future<size_t> send(transfer_ptr data, int64_t timeout_ms = 1600) noexcept(false) = 0;
        virtual std::future<size_t> receive(transfer_ptr data, int64_t timeout_ms = 1600) noexcept(false) = 0;
    };

    std::shared_ptr<udp_client> create_udp_client(const std::string& address = "127.0.0.1", uint16_t port = 5000);
}}
