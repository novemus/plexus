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

#include <logger.h>
#include <cstdlib>
#include <string>
#include <iostream>
#include <chrono>
#include <random>
#include <regex>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ip/udp.hpp>

namespace plexus { namespace utils {

std::string to_hexadecimal(const void* data, size_t len);
std::string to_base64(const void* data, size_t length);
std::string to_base64_no_nl(const void* data, size_t length);
std::string to_base64_url(const void* data, size_t length);
std::string from_base64(const char* data, size_t length);
std::string from_base64_url(const char* data, size_t length);
std::string format(const std::string& format, ...);
std::string format(const std::string& format, const boost::posix_time::ptime& time);
std::string format(const std::string& format, const std::chrono::system_clock::time_point& time);
std::string smime_sign(const std::string& msg, const std::string& cert, const std::string& key);
std::string smime_verify(const std::string& msg, const std::string& cert, const std::string& ca);
std::string smime_encrypt(const std::string& msg, const std::string& cert);
std::string smime_decrypt(const std::string& msg, const std::string& cert, const std::string& key);

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

template<class endpoint>
endpoint parse_endpoint(const std::string& url, const std::string& service)
{
    if (url.empty() && service.empty())
        return endpoint();

    boost::asio::io_context io;
    typename endpoint::protocol_type::resolver resolver(io);

    std::smatch match;
    if (std::regex_search(url, match, std::regex("^(\\w+://)?([^/]+):(\\d+)?$")))
        return *resolver.resolve(match[2].str(), match[3].str());
    
    if (std::regex_search(url, match, std::regex("^(\\w+)://([^/]+).*$")))
        return *resolver.resolve(match[2].str(), match[1].str());

    return *resolver.resolve(url, service);
}

}

template<class byte>
std::ostream& operator<<(std::ostream& stream, const std::pair<byte*, size_t>& buffer)
{
    if (stream.rdbuf())
        return stream << plexus::utils::to_hexadecimal(buffer.first, buffer.second);
    return stream;
}

template<class proto>
std::ostream& operator<<(std::ostream& stream, const boost::asio::ip::basic_endpoint<proto>& endpoint)
{
    if (stream.rdbuf())
        return stream << endpoint.address().to_string() << ":" << endpoint.port();
    return stream;
}

}
