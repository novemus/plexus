#include <plexus/utils.h>
#include <wormhole/logger.h>

#include <vector>
#include <string>
#include <filesystem>
#include <csignal>
#include <stdexcept>

#include <boost/filesystem.hpp>
#include <boost/tokenizer.hpp>
#include <boost/version.hpp>

#if BOOST_VERSION >= 108800
    #include <boost/process/v1/child.hpp>
    #ifdef WIN32
        #include <boost/process/v1/windows.hpp>
    #endif
    #if defined WIN32 || __APPLE__
        #include <boost/process/v1/env.hpp>
        #include <boost/process/v1/args.hpp>
        #include <boost/process/v1/start_dir.hpp>
        #include <boost/process/v1/io.hpp>
        #include <boost/process/v1/extend.hpp>
    #else
        #include <spawn.h>
        #include <boost/process/v1/extend.hpp>
    #endif
    namespace bp = boost::process::v1;
#else
    #include <boost/process.hpp>
    #ifdef WIN32
        #include <boost/process/windows.hpp>
        #include <boost/process/windows/creation_flags.hpp>
    #else
        #include <spawn.h>
        #include <boost/process/extend.hpp>
    #endif
    namespace bp = boost::process;
#endif

namespace plexus { namespace utils
{
    std::vector<std::string> make_args(const std::string& args)
    {
        std::vector<std::string> list;
        if (args.empty())
            return list;

        boost::tokenizer<boost::escaped_list_separator<char>> tok(args, boost::escaped_list_separator<char>("\\", " \t", "'\""));
        for (const auto& t : tok) 
        {
            if (!t.empty())
                list.push_back(t);
        }
        return list;
    }

    bp::environment make_env(const std::string& extra)
    {
        bp::environment env = boost::this_process::environment();
        if (extra.empty())
            return env;

        boost::tokenizer<boost::escaped_list_separator<char>> tok(extra, boost::escaped_list_separator<char>("\\", " \t", "'\""));
        for (const auto& s : tok)
        {
            if (s.empty())
                continue;

            size_t delim = s.find('=');
            if (delim == std::string::npos)
                throw std::runtime_error("can't parse extra environment");

            env[s.substr(0, delim)] = s.substr(delim + 1);
        }
        return env;
    }

    inline std::string make_workdir(const std::string& dir)
    {
        return dir.empty() ? std::filesystem::current_path().string() : dir;
    }
}

void exec(const std::string& exe, const std::string& args, const std::string& dir, const std::string& log, const std::string& env, bool wait) 
{
    _dbg_ << "execute: exe=" << exe << " args=" << args << " pwd=" << dir << " log=" << log << " wait=" << wait;

    auto finalize = [](bp::child& c, bool wait)
    {
        _dbg_ << "run process " << c.id();

        if (wait)
        {
            if (!c.running())
                c.join();
            else
                c.wait();

            if (c.exit_code() != 0)
                throw std::runtime_error(utils::format("process %d exited with code: %d", c.id(), c.exit_code()));
        } 
        else
        {
            c.detach();
        }
    };

    if (!log.empty())
    {
        if (wait)
        {
            bp::child c(
                exe, bp::args = utils::make_args(args),
                bp::env = utils::make_env(env),
                bp::start_dir = utils::make_workdir(dir),
                (bp::std_out & bp::std_err) > log,
                bp::std_in < stdin
#ifdef WIN32
                , bp::windows::hide
#endif
            );
            finalize(c, true);
        }
        else
        {
            bp::child c(
                exe, bp::args = utils::make_args(args),
                bp::env = utils::make_env(env),
                bp::start_dir = utils::make_workdir(dir),
                (bp::std_out & bp::std_err) > log,
                bp::std_in < bp::null,
#ifdef WIN32
                bp::extend::on_setup([](auto& ctx) { ctx.creation_flags |= DETACHED_PROCESS; }),
                bp::windows::hide
#else
                bp::extend::on_exec_setup([](auto & exec) { ::setsid(); })
#endif
            );
            finalize(c, false);
        }
    }
    else if (wait)
    {
        bp::child c(
            exe, bp::args = utils::make_args(args),
            bp::env = utils::make_env(env),
            bp::start_dir = utils::make_workdir(dir),
            bp::std_out > stdout,
            bp::std_err > stderr,
            bp::std_in < stdin
#ifdef WIN32
            , bp::windows::hide
#endif
        );
        finalize(c, true);
    }
    else
    {
        bp::child c(
            exe, bp::args = utils::make_args(args),
            bp::env = utils::make_env(env),
            bp::start_dir = utils::make_workdir(dir),
            bp::std_out > bp::null,
            bp::std_err > bp::null,
            bp::std_in < bp::null,
#ifdef WIN32
            bp::extend::on_setup([](auto& ctx) { ctx.creation_flags |= DETACHED_PROCESS; }),
            bp::windows::hide
#else
            bp::extend::on_exec_setup([](auto & exec) { ::setsid(); })
#endif
        );
        finalize(c, false);
    }
}

}
