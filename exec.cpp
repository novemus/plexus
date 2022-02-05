#include <spawn.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <memory>
#include <vector>
#include <boost/algorithm/string/replace.hpp>
#include "features.h"
#include "utils.h"

extern char **environ;

namespace plexus {

std::shared_ptr<char*> copy_environment()
{
    std::vector<char*> list;
    for (char **env = ::environ; *env; ++env)
    {
		list.push_back(*env);
	}

    std::shared_ptr<char*> environment(new char *[list.size() + 1], std::default_delete<char *[]>());
    char **ptr = environment.get();
    for (size_t i = 0; i < list.size(); ++i)
    {
		ptr[i] = list[i];
	}
    ptr[list.size()] = 0;

    return environment;
}

void exec(const std::string& prog, const std::string& args, const std::string& dir, const std::string& log)
{
    std::string cmd = boost::replace_all_copy(prog, " ", "\\ ");
    cmd += " " + args;

    std::string pwd = boost::replace_all_copy(dir, " ", "\\ ");
    std::string command = pwd.empty() ? cmd : "cd " + pwd + " && " + cmd;

    const char* argv[] = { "sh", "-c", command.c_str(), 0 };
    std::shared_ptr<char*> env = copy_environment();

    posix_spawn_file_actions_t action = {};
    int status = posix_spawn_file_actions_init(&action);
    if (status)
        throw std::runtime_error(utils::format("posix_spawn_file_actions_init: error=%d", status));

    if (!log.empty())
    {
        status = posix_spawn_file_actions_addopen(&action, 1, log.c_str(), O_CREAT | O_APPEND | O_WRONLY, 0644);
        if (status)
            throw std::runtime_error(utils::format("posix_spawn_file_actions_addopen: error=%d", status));
        
        status = posix_spawn_file_actions_adddup2(&action, 1, 2);
        if (status)
            throw std::runtime_error(utils::format("posix_spawn_file_actions_adddup2: error=%d", status));
    }

    pid_t pid;
    status = posix_spawn(&pid, "/bin/sh", &action, 0, (char*const*)argv, env.get());
    if (status)
        throw std::runtime_error(utils::format("posix_spawn: error=%d", status));

    if (waitpid(pid, &status, 0) == -1)
        throw std::runtime_error(utils::format("waitpid: error=%d", errno));

    if (WIFSIGNALED(status))
        throw std::runtime_error(utils::format("signal=%d", WTERMSIG(status)));

    else if (WIFSTOPPED(status))
        throw std::runtime_error(utils::format("signal=%d", WSTOPSIG(status)));

    status = posix_spawn_file_actions_destroy(&action);
    if (status)
        throw std::runtime_error(utils::format("posix_spawn_file_actions_destroy: error=%d", status));
}

}
