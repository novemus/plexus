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

#include <cstdlib>
#include <string>
#include <iostream>
#include <chrono>
#include <random>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/lexical_cast.hpp>

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
    catch (const boost::bad_lexical_cast& ex) {}

    return def;
}

}

template<class type>
std::ostream& operator<<(std::ostream& stream, const std::pair<type*, size_t>& buf)
{
    return stream << plexus::utils::to_hexadecimal(buf.first, sizeof(type) * buf.second);
}

}
