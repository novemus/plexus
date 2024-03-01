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
#include <vector>

#ifdef _WIN32

#include <windows.h>
#include <processthreadsapi.h>

namespace plexus {

void exec(const std::string& prog, const std::string& args, const std::string& dir, const std::string& log, bool wait)
{
    _dbg_ << "execute cmd=\"" << prog << "\" args=\"" << args << "\" pwd=\"" << dir << "\" log=\"" << log << "\"";

	std::string cmd = "\"" + prog + "\" " + args;

	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	std::memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
    si.dwFlags |= STARTF_USESTDHANDLES;
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

        si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
        si.hStdOutput = h;
        si.hStdError = h;
    }
    else
    {
        si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
        si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    }

	if (CreateProcess(prog.c_str(), (char*)cmd.c_str(), 0, 0, true, 0, 0, dir.empty() ? 0 : dir.c_str(), &si, &pi))
	{
        if (wait)
        {
            WaitForSingleObject(pi.hProcess, INFINITE);

            DWORD code = 0;
            if (!GetExitCodeProcess(pi.hProcess, &code) || code != 0)
            {
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);

                if (!log.empty())
                    CloseHandle(si.hStdOutput);

                throw std::runtime_error(utils::format("GetExitCodeProcess: error=%d, code=%d", GetLastError(), code));
            }
        }

        if (!log.empty())
            CloseHandle(si.hStdOutput);

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

void exec(const std::string& prog, const std::string& args, const std::string& dir, const std::string& log, bool wait)
{
    _dbg_ << "execute cmd=\"" << prog << "\" args=\"" << args << "\" pwd=\"" << dir << "\" log=\"" << log << "\"";

    std::string cmd = boost::replace_all_copy(prog, " ", "\\ ");
    cmd += " " + args;

    std::string pwd = boost::replace_all_copy(dir, " ", "\\ ");
    std::string command = pwd.empty() ? cmd : "cd " + pwd + " && " + cmd;
    if (!wait)
        command += " &";

    const char* argv[] = { "sh", "-c", command.c_str(), 0 };

    std::vector<char*> envp;
    for (char **env = ::environ; *env; ++env)
        envp.push_back(*env);
    envp.push_back(0);

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
    status = posix_spawn(&pid, "/bin/sh", &action, 0, (char*const*)argv, envp.data());
    if (status)
        throw std::runtime_error(utils::format("posix_spawn: error=%d", status));

    int code = 0;
    if (waitpid(pid, &code, 0) == -1)
        throw std::runtime_error(utils::format("waitpid: error=%d", errno));

    status = posix_spawn_file_actions_destroy(&action);
    if (status)
        throw std::runtime_error(utils::format("posix_spawn_file_actions_destroy: error=%d", status));
    if (WIFSIGNALED(code))
        throw std::runtime_error(utils::format("signal=%d", WTERMSIG(code)));
    if (WIFSTOPPED(code))
        throw std::runtime_error(utils::format("signal=%d", WSTOPSIG(code)));
    if (code)
        throw std::runtime_error(utils::format("exit: error=%d", code));
}

}

#endif
