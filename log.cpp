#include <fstream>
#include <sys/types.h>
#include <boost/thread/thread.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include "log.h"

namespace plexus { namespace log {

std::function<std::ostream&()> get_stream = []() -> std::ostream& { return std::cout; };
std::function<severity()> get_severity = []() -> severity { return severity::info; };

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
        case debug:
            return out << "DEBUG";
        case trace:
            return out << "TRACE";
        default:
            return out << "INFO";
    }
    return out;
}

logger::logger(severity l) : level(l > get_severity() ? severity::none : l)
{
    if (level != severity::none)
    {
        stream << boost::posix_time::microsec_clock::local_time() << " [" << gettid() << "] " << level << ": ";
    }
}

logger::~logger()
{
    static std::mutex s_mutex;

    if (level != severity::none)
    {
        std::lock_guard<std::mutex> guard(s_mutex);

        std::ostream& out = get_stream();
        out << stream.rdbuf() << std::endl;
        out.flush();
    }
}

void init(severity level, const char* file)
{
    if (file)
    {
        static std::ofstream s_log(file);
        get_stream = []() -> std::ofstream& { return s_log; };
    }
    get_severity = [level]() -> severity { return level; };
}

}}
