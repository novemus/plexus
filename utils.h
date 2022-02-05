#pragma once

#include <string>
#include <iostream>
#include <boost/date_time/posix_time/posix_time.hpp>

namespace plexus { namespace utils {

std::string to_hexadecimal(uint8_t* data, size_t len);
std::string to_base64(const void* data, size_t length);
std::string to_base64_no_nl(const void* data, size_t length);
std::string to_base64_url(const void* data, size_t length);
std::string from_base64(const char* data, size_t length);
std::string from_base64_url(const char* data, size_t length);
std::string format(const std::string& format, ...);
std::string format(const std::string& format, const boost::posix_time::ptime& time);

}}
