/*
 * Copyright (c) 2022 Novemus Band. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 */

#include "features.h"
#include "utils.h"
#include <logger.h>
#include <fcntl.h>
#include <memory>
#include <vector>
#include <boost/algorithm/string/replace.hpp>

#ifdef _WIN32

#include <windows.h>
#include <processthreadsapi.h>

namespace plexus {

void exec(const std::string& prog, const std::string& args, const std::string& dir, const std::string& log)
{
    _dbg_ << "execute cmd=\"" << prog << "\" args=\"" << args << "\" pwd=\"" << dir << "\" log=\"" << log << "\"";

	std::string cmd = "\"" + prog + "\" " + args;

	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	std::memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	std::memset(&pi, 0, sizeof(pi));

    if (!log.empty())
    {
        SECURITY_ATTRIBUTES sa;
        sa.nLength = sizeof(sa);
        sa.lpSecurityDescriptor = NULL;
        sa.bInheritHandle = TRUE;  

        HANDLE h = CreateFile(log.c_str(),
            FILE_APPEND_DATA,
            FILE_SHARE_WRITE | FILE_SHARE_READ,
            &sa,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL);

        if (h == INVALID_HANDLE_VALUE)
            throw std::runtime_error(utils::format("CreateFile: error=%d", GetLastError()));

        si.dwFlags |= STARTF_USESTDHANDLES;
        si.hStdError = h;
        si.hStdOutput = h;
    }

	if (CreateProcess(prog.c_str(), (char*)cmd.c_str(), 0, 0, true, CREATE_NO_WINDOW, 0, dir.empty() ? 0 : dir.c_str(), &si, &pi))
	{
		WaitForSingleObject(pi.hProcess, INFINITE);

		DWORD code = 0;
		if (!GetExitCodeProcess(pi.hProcess, &code) || code != 0)
		{
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);

			throw std::runtime_error(utils::format("GetExitCodeProcess: error=%d, code=%d", GetLastError(), code));
		}

		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}
	else
	{
		throw std::runtime_error(utils::format("CreateProcess: error=%d", GetLastError()));
	}
}

}

#else

#include <spawn.h>
#include <sys/wait.h>

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
    _dbg_ << "execute cmd=\"" << prog << "\" args=\"" << args << "\" pwd=\"" << dir << "\" log=\"" << log << "\"";

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
        std::string outfile = boost::replace_all_copy(log, " ", "\\ ");
        status = posix_spawn_file_actions_addopen(&action, 1, outfile.c_str(), O_CREAT | O_APPEND | O_WRONLY, 0644);
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

#endif
