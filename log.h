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

void set(severity level, const std::string& file = "");

}}

#define _ftl_ plexus::log::line(plexus::log::fatal)
#define _err_ plexus::log::line(plexus::log::error)
#define _wrn_ plexus::log::line(plexus::log::warning)
#define _inf_ plexus::log::line(plexus::log::info)
#define _dbg_ plexus::log::line(plexus::log::debug)
#define _trc_ plexus::log::line(plexus::log::trace)
