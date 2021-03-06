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

#include <string>
#include <iostream>
#include <chrono>
#include <boost/date_time/posix_time/posix_time.hpp>

namespace plexus { namespace utils {

std::string to_hexadecimal(const uint8_t* data, size_t len);
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
uint64_t random();

}}
