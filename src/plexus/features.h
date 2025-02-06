/*
 * Copyright (c) 2022 Novemus Band. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 */

#pragma once

#include <plexus/plexus.h>
#include <plexus/network.h>
#include <plexus/utils.h>
#include <string>
#include <filesystem>
#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>

namespace plexus {

struct context_error : public std::runtime_error
{ 
    context_error(const std::string& loc, const std::string& msg) 
        : std::runtime_error(utils::format("%s: %s", loc.c_str(), msg.c_str())) 
    {} 
    
    context_error(const std::string& loc, const boost::system::error_code& code) 
        : std::runtime_error(utils::format("%s: %s", loc.c_str(), code.message().c_str())) 
    {} 
};

struct timeout_error : public context_error
{ 
    timeout_error(const std::string& loc) 
        : context_error(loc, "timeout error") 
    {} 
};

static constexpr const char* cert_file_name = "cert.crt";
static constexpr const char* key_file_name = "private.key";
static constexpr const char* ca_file_name = "ca.crt";

void exec(const std::string& prog, const std::string& args = "", const std::string& dir = "", const std::string& log = "", bool wait = false) noexcept(false);

std::ostream& operator<<(std::ostream& stream, const reference& value);
std::ostream& operator<<(std::ostream& stream, const identity& value);
std::istream& operator>>(std::istream& in, reference& level);
std::istream& operator>>(std::istream& in, identity& level);

struct stun_client
{
    virtual ~stun_client() {}
    virtual network::traverse punch_hole(boost::asio::yield_context yield) noexcept(false) = 0;
};

std::shared_ptr<stun_client> create_stun_client(boost::asio::io_service& io, const boost::asio::ip::udp::endpoint& stun, const boost::asio::ip::udp::endpoint& bind) noexcept(true);

struct stun_binder : public stun_client
{
    virtual void reach_peer(boost::asio::yield_context yield, const boost::asio::ip::udp::endpoint& peer, uint64_t mask) noexcept(false) = 0;
    virtual void await_peer(boost::asio::yield_context yield, const boost::asio::ip::udp::endpoint& peer, uint64_t mask) noexcept(false) = 0;
};

std::shared_ptr<stun_binder> create_stun_binder(boost::asio::io_service& io, const boost::asio::ip::udp::endpoint& stun, const boost::asio::ip::udp::endpoint& bind, uint16_t punch) noexcept(true);

struct pipe
{
    virtual ~pipe() {}
    virtual reference pull_request(boost::asio::yield_context yield) noexcept(false) = 0;
    virtual reference pull_response(boost::asio::yield_context yield) noexcept(false) = 0;
    virtual void push_response(boost::asio::yield_context yield, const reference& gateway) noexcept(false) = 0;
    virtual void push_request(boost::asio::yield_context yield, const reference& gateway) noexcept(false) = 0;
    virtual const identity& host() const noexcept(true) = 0;
    virtual const identity& peer() const noexcept(true) = 0;
};

using coroutine = std::function<void(boost::asio::yield_context yield, std::shared_ptr<pipe> pipe)>;

template<class mediator> struct context : public mediator
{
    std::string app;
    std::string repo;

    context(const std::string& app, const std::string& repo, const mediator& conf) noexcept(true) 
        : mediator(conf)
        , app(app)
        , repo(repo)
    {
    }

    context(const context& conf) noexcept(true) 
        : mediator(conf)
        , app(conf.app)
        , repo(conf.repo)
    {
    }

    bool are_defined(const identity& host, const identity& peer) const noexcept(true)
    {
        return !host.owner.empty() && !host.pin.empty() && !peer.owner.empty() && !peer.pin.empty();
    }

    bool matched(const identity& host, const identity& peer) const noexcept(true)
    {
        return !host.owner.empty() && !host.pin.empty() && !peer.owner.empty() && !peer.pin.empty();
    }

    bool are_allowed(const identity& host, const identity& peer) const noexcept(false)
    {
        return are_defined(host, peer)
            && std::filesystem::exists(std::filesystem::path(std::filesystem::path(repo) / host.owner / host.pin))
            && std::filesystem::exists(std::filesystem::path(std::filesystem::path(repo) / peer.owner / peer.pin));
    }

    bool are_encryptable(const identity& host, const identity& peer) const noexcept(false)
    {
        return std::filesystem::exists(std::filesystem::path(std::filesystem::path(repo) / host.owner / host.pin / cert_file_name))
            && std::filesystem::exists(std::filesystem::path(std::filesystem::path(repo) / host.owner / host.pin / key_file_name))
            && std::filesystem::exists(std::filesystem::path(std::filesystem::path(repo) / peer.owner / peer.pin / cert_file_name));
    }

    bool has_cert(const identity& info) const noexcept(false)
    {
        return std::filesystem::exists(std::filesystem::path(std::filesystem::path(repo) / info.owner / info.pin / cert_file_name));
    }

    bool has_key(const identity& info) const noexcept(false)
    {
        return std::filesystem::exists(std::filesystem::path(std::filesystem::path(repo) / info.owner / info.pin / key_file_name));
    }

    bool has_ca(const identity& info) const noexcept(false)
    {
        return std::filesystem::exists(std::filesystem::path(std::filesystem::path(repo) / info.owner / info.pin / ca_file_name));
    }

    std::string get_cert(const identity& info) const noexcept(false)
    {
        std::filesystem::path cert(std::filesystem::path(repo) / info.owner / info.pin / cert_file_name);
        return std::filesystem::exists(cert) ? cert.generic_u8string() : "";
    }

    std::string get_key(const identity& info) const noexcept(false)
    {
        std::filesystem::path key(std::filesystem::path(repo) / info.owner / info.pin / key_file_name);
        return std::filesystem::exists(key) ? key.generic_u8string() : "";
    }

    std::string get_ca(const identity& info) const noexcept(false)
    {
        std::filesystem::path ca(std::filesystem::path(repo) / info.owner / info.pin / ca_file_name);
        return std::filesystem::exists(ca) ? ca.generic_u8string() : "";
    }
};

template<class mediator>
void spawn_accept(boost::asio::io_service& io, const context<mediator>& conf, const identity& host, const identity& peer, const coroutine& handler) noexcept(true);
template<class mediator>
void spawn_invite(boost::asio::io_service& io, const context<mediator>& conf, const identity& host, const identity& peer, const coroutine& handler) noexcept(true);

}
