#include <fstream>
#include <mutex>
#include <future>
#include <sys/types.h>
#include <boost/thread/thread.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include "log.h"

#if __GLIBC__ == 2 && __GLIBC_MINOR__ < 30
#include <sys/syscall.h>
#define gettid() syscall(SYS_gettid)
#elif _WIN32
#include <windows.h>
#include <processthreadsapi.h>
#define gettid() GetCurrentThreadId()
#endif

namespace plexus { namespace log {

severity      g_level(severity::info);
std::ofstream g_file;
std::mutex    g_mutex;

void append(const std::string& line) 
{
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_file.is_open())
        g_file << line << std::endl;
    else
        std::cout << line << std::endl;
};

severity level()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_level;
}

std::ostream& operator<<(std::ostream& out, severity severity)
{
    switch(severity)
    {
        case fatal:
            return out << "FATAL";
        case error:
            return out << "ERROR";
        case warning:
            return out << "WARN";
        case info:
            return out << "INFO";
        case debug:
            return out << "DEBUG";
        case trace:
            return out << "TRACE";
        default:
            return out << "NONE";
    }
    return out;
}

line::line(severity l) : level(l <= log::level() ? l : severity::none)
{
    if (level != severity::none)
    {
        stream << boost::posix_time::microsec_clock::local_time() << " [" << gettid() << "] " << level << ": ";
    }
}

line::~line()
{
    if (level != severity::none)
    {
        log::append(stream.str());
    }
}

void set(severity level, const std::string& file)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    if (file.empty())
    {
        g_file.close();
    }
    else
    {
        g_file.open(file);
    }
    g_level = level;
}

}}
