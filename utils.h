#pragma once

#include <string>
#include <chrono>

namespace utils
{
    std::string to_base64(const void* data, size_t length);
    std::string to_base64_no_nl(const void* data, size_t length);
    std::string to_base64_url(const void* data, size_t length);
    std::string from_base64(const char* data, size_t length);
    std::string from_base64_url(const char* data, size_t length);
    std::string format(const std::string& format, ...);
    std::string format(const std::string& format, const std::chrono::system_clock::time_point& time);
}
