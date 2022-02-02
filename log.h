#pragma once

#include <mutex>
#include <ostream>
#include <sstream>
#include <functional>

namespace plexus { namespace log {

enum severity
{
    none,
    fatal,
    error,
    warning,
    info,
    debug,
    trace
};

struct logger
{
    logger(severity level);
    ~logger();
    
    template<typename type_t> 
    logger& operator<<(const type_t& value)
    {
        if (level != severity::none)
            stream << value;
        return *this;
    }

private:

    severity level;
    std::stringstream stream;
};

void init(severity level, const char* file = 0);

}}

#define _ftl_ plexus::log::logger(plexus::log::fatal)
#define _err_ plexus::log::logger(plexus::log::error)
#define _wrn_ plexus::log::logger(plexus::log::warning)
#define _inf_ plexus::log::logger(plexus::log::info)
#define _dbg_ plexus::log::logger(plexus::log::debug)
#define _trc_ plexus::log::logger(plexus::log::trace)
