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

#include <wormhole/logger.h>
#include <plexus/plexus.h>
#include <cstdlib>
#include <string>
#include <iostream>
#include <sstream>
#include <chrono>
#include <random>
#include <regex>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/asio.hpp>

namespace plexus { namespace utils {

std::string to_hexadecimal(const void* data, size_t len);
std::string to_base64(const void* data, size_t length);
std::string to_base64_no_nl(const void* data, size_t length);
std::string to_base64_url(const void* data, size_t length);
std::string from_base64(const char* data, size_t length);
std::string from_base64_url(const char* data, size_t length);
std::string format(const char* fmt, ...);
std::string format(const char* fmt, const boost::posix_time::ptime& time);
std::string format(const char* fmt, const std::chrono::system_clock::time_point& time);
std::string smime_sign(const std::string& msg, const std::string& cert, const std::string& key);
std::string smime_verify(const std::string& msg, const std::string& cert, const std::string& ca);
std::string smime_encrypt(const std::string& msg, const std::string& cert);
std::string smime_decrypt(const std::string& msg, const std::string& cert, const std::string& key);
std::string get_email_address(const std::string& email);

template<class var_t> var_t random()
{
    std::random_device dev;
    std::mt19937_64 gen(dev());
    return static_cast<var_t>(gen());
}

template<class var_t> var_t getenv(const std::string& name, const var_t& def)
{
    try
    {
        const char *env = std::getenv(name.c_str());
        return env ? boost::lexical_cast<var_t>(env) : def;
    }
    catch (const boost::bad_lexical_cast& ex)
    {
        _err_ << ex.what();
    }

    return def;
}

template<class protocol>
endpoint resolve_some(const std::string& hostname, const std::string& service)
{
    if (hostname.empty())
        return endpoint {};

    boost::asio::io_context io;
    typename protocol::resolver resolver(io);
    typename protocol::endpoint ep;

    try
    {
        std::smatch match;
        if (std::regex_search(hostname, match, std::regex("^\\[(.+)\\]:(\\d+)$")))
            ep = *resolver.resolve(match[1].str(), match[2].str()).begin();
        else if (std::regex_search(hostname, match, std::regex("^(.+):(\\d+)$")))
            ep = *resolver.resolve(match[1].str(), match[2].str()).begin();
        else
            ep = *resolver.resolve(hostname, service).begin();
    }
    catch(const std::exception& ex)
    {
        throw std::runtime_error("can't resolve '" + hostname + "' endpoint: " + ex.what());
    }

    return endpoint { ep.address(), ep.port() };
}

template<class protocol>
endpoint resolve_same(const boost::asio::ip::address& address, const std::string& hostname, const std::string& service)
{
    boost::asio::io_context io;
    typename protocol::resolver resolver(io);
    typename protocol::endpoint ep;

    try
    {
        std::smatch match;
        if (address.is_v6() && std::regex_search(hostname, match, std::regex("^\\[(.+)\\]:(\\d+)$")))
            ep = *resolver.resolve(protocol::v6(), match[1].str(), match[2].str()).begin();
        else if(address.is_v4() && std::regex_search(hostname, match, std::regex("^(.+):(\\d+)$")))
            ep = *resolver.resolve(protocol::v4(), match[1].str(), match[2].str()).begin();
        else
            ep = *resolver.resolve(address.is_v4() ? protocol::v4() : protocol::v6(), hostname, service).begin();
    }
    catch(const std::exception& ex)
    {
        throw std::runtime_error("can't resolve '" + hostname + "' endpoint: " + ex.what());
    }

    return endpoint { ep.address(), ep.port() };
}

template<class protocol>
endpoint locate(const endpoint& local)
{
    if (local.port == 0)
    {
        boost::asio::io_context io;
        typename protocol::socket socket(io, local.address.is_v6() ? protocol::v6() : protocol::v4());
        socket.set_option(boost::asio::socket_base::reuse_address(true));
        socket.bind(local);
        auto ep = socket.local_endpoint();
        return endpoint { ep.address(), ep.port() };
    }
    return local;
}

template <typename type>
std::string to_string(const type& value)
{
    std::ostringstream oss;
    oss << value;
    return oss.str();
}

template <typename type>
type from_string(const std::string& str)
{
    std::istringstream iss(str);
    type value;
    iss >> value;
    return value;
}

}}
