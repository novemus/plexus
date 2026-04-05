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

template<class proto>
boost::asio::ip::basic_endpoint<proto> parse_endpoint(const std::string& url, const std::string& service)
{
    if (url.empty() && service.empty())
        return boost::asio::ip::basic_endpoint<proto>();

    boost::asio::io_context io;
    typename proto::resolver resolver(io);

    std::smatch match;
    if (std::regex_search(url, match, std::regex("^(\\w+://)?\\[([a-zA-Z0-9:]+)\\]:(\\d+).*")))
        return *resolver.resolve(match[2].str(), match[3].str()).begin();

    if (std::regex_search(url, match, std::regex("^(\\w+)://\\[([a-zA-Z0-9:]+)\\].*")))
        return *resolver.resolve(match[2].str(), match[1].str()).begin();

    if (std::regex_search(url, match, std::regex("^\\[([a-zA-Z0-9:]+)\\].*")))
        return *resolver.resolve(match[1].str(), service).begin();

    if (std::regex_search(url, match, std::regex("^(\\w+://)?([\\w\\.]+):(\\d+).*")))
        return *resolver.resolve(match[2].str(), match[3].str()).begin();

    if (std::regex_search(url, match, std::regex("^(\\w+)://([\\w\\.]+).*")))
        return *resolver.resolve(match[2].str(), match[1].str()).begin();

    return *resolver.resolve(url, service).begin();
}

template<class proto>
endpoint locate(const endpoint& ep)
{
    if (ep.port == 0)
    {
        boost::asio::io_context io;
        typename proto::socket socket(io, ep.address.is_v6() ? proto::v6() : proto::v4());
        socket.set_option(boost::asio::socket_base::reuse_address(true));
        socket.bind(ep);

        auto ep = socket.local_endpoint();
        return endpoint { ep.address(), ep.port() };
    }
    return ep;
}

}

template<class proto>
std::ostream& operator<<(std::ostream& stream, const boost::asio::ip::basic_endpoint<proto>& endpoint)
{
    if (stream.rdbuf())
        return stream << endpoint.address().to_string() << ":" << endpoint.port();
    return stream;
}

}
