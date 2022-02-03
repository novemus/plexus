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

struct line
{
    line(severity level);
    ~line();
    
    template<typename type_t> 
    line& operator<<(const type_t& value)
    {
        if (level != severity::none)
            stream << value;
        return *this;
    }

private:

    severity level;
    std::stringstream stream;
};

void set(severity level, const char* file = 0);

}}

#define _ftl_ plexus::log::line(plexus::log::fatal)
#define _err_ plexus::log::line(plexus::log::error)
#define _wrn_ plexus::log::line(plexus::log::warning)
#define _inf_ plexus::log::line(plexus::log::info)
#define _dbg_ plexus::log::line(plexus::log::debug)
#define _trc_ plexus::log::line(plexus::log::trace)
