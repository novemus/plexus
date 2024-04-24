/*
 * Copyright (c) 2022 Novemus Band. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 */

#include "utils.h"
#include <logger.h>

#ifdef _WIN32

#include <windows.h>
#include <processthreadsapi.h>
#include <filesystem>

namespace plexus {

struct waiter
{
    HANDLE handle;
    HANDLE process_handle;
    DWORD  process_id;

    static void notify(PVOID data, BOOLEAN timeout)
    {
        waiter* ptr = static_cast<waiter*>(data);

        DWORD code;
        if (!GetExitCodeProcess(ptr->process_handle, &code))
            _wrn_ << "can't get child process " << ptr->process_id << " exit code: error=" << GetLastError();
        else
            _inf_ << "got child process " << ptr->process_id << " exit code: " << code;

        CloseHandle(ptr->process_handle);
        UnregisterWait(ptr->handle);

        delete ptr;
    }
};

void exec(const std::string& prog, const std::string& args, const std::string& dir, const std::string& log, bool wait) noexcept(false)
{
    _dbg_ << "execute: cmd=\"" << prog << "\" args=\"" << args << "\" pwd=\"" << dir << "\" log=\"" << log << "\"";

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

        auto path = std::filesystem::path(log);
        if (!dir.empty() && path.is_relative())
            path = std::filesystem::path(dir) / path;

        HANDLE h = CreateFile(path.string().c_str(),
            FILE_APPEND_DATA,
            FILE_SHARE_WRITE | FILE_SHARE_READ,
            &sa,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL);

        if (h == INVALID_HANDLE_VALUE)
            throw std::runtime_error(utils::format("CreateFile: error=%d", GetLastError()));

        if(wait)
            si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

        si.hStdOutput = h;
        si.hStdError = h;
    }
    else if (wait)
    {
        si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
        si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    }

	if (CreateProcess(prog.c_str(), (char*)cmd.c_str(), 0, 0, true, wait ? 0 : CREATE_NO_WINDOW, 0, dir.empty() ? 0 : dir.c_str(), &si, &pi))
	{
        _inf_ << "execute: pid=" << pi.dwProcessId;

        if (!log.empty())
            CloseHandle(si.hStdOutput);
        
        CloseHandle(pi.hThread);

        if (wait)
        {
            WaitForSingleObject(pi.hProcess, INFINITE);

            DWORD code = 0;
            if (!GetExitCodeProcess(pi.hProcess, &code) || code != 0)
            {
                CloseHandle(pi.hProcess);
                throw std::runtime_error(utils::format("GetExitCodeProcess: error=%d, code=%d", GetLastError(), code));
            }
            CloseHandle(pi.hProcess);
        }
        else
        {
            waiter* ptr = new waiter { 0, pi.hProcess, pi.dwProcessId };
            if (!RegisterWaitForSingleObject(&ptr->handle, pi.hProcess, &waiter::notify, ptr, INFINITE, WT_EXECUTEONLYONCE))
            {
                CloseHandle(pi.hProcess);
                throw std::runtime_error(utils::format("RegisterWaitForSingleObject: error=%d", GetLastError()));
            }
        }
	}
	else
	{
		throw std::runtime_error(utils::format("CreateProcess: error=%d", GetLastError()));
	}
}

}

#else

#include <fcntl.h>
#include <spawn.h>
#include <sys/wait.h>
#include <boost/program_options.hpp>
#include <vector>

extern char **environ;

namespace plexus {

void exec(const std::string& prog, const std::string& args, const std::string& dir, const std::string& log, bool wait) noexcept(false)
{
    _dbg_ << "execute: cmd=\"" << prog << "\" args=\"" << args << "\" pwd=\"" << dir << "\" log=\"" << log << "\"";

    static std::once_flag s_flag;
    std::call_once(s_flag, []()
    {
        signal(SIGCHLD, [](int num)
        {
            pid_t pid = waitpid(-1, &num, WNOHANG);
            while (pid > 0)
            {
                _inf_ << "got child process " << pid << " exit code: " << num;
                pid = waitpid(-1, &num, WNOHANG);
            }
        });
    });

    auto exe = boost::replace_all_copy(prog, " ", "\\ ");
    auto arguments = boost::program_options::split_unix(args);

    std::vector<char*> argv;
    argv.push_back(exe.data());
    for (auto& arg : arguments)
        argv.push_back(arg.data());
    argv.push_back(0);

    posix_spawn_file_actions_t action;
    int status = posix_spawn_file_actions_init(&action);
    if (status)
        throw std::runtime_error(utils::format("posix_spawn_file_actions_init: error=%d", status));

    if (!dir.empty())
    {
        std::string pwd = boost::replace_all_copy(dir, " ", "\\ ");
        status = posix_spawn_file_actions_addchdir_np(&action, pwd.c_str());
        if (status)
            throw std::runtime_error(utils::format("posix_spawn_file_actions_addchdir_np: error=%d", status));
    }

    if (!wait)
    {
        status = posix_spawn_file_actions_addclose(&action, 0);
        if (status)
            throw std::runtime_error(utils::format("posix_spawn_file_actions_addclose stdin: error=%d", status));

        status = posix_spawn_file_actions_addclose(&action, 1);
        if (status)
            throw std::runtime_error(utils::format("posix_spawn_file_actions_addclose stdout: error=%d", status));

        status = posix_spawn_file_actions_addclose(&action, 2);
        if (status)
            throw std::runtime_error(utils::format("posix_spawn_file_actions_addclose stderr: error=%d", status));
    }

    if (!log.empty())
    {
        std::string out = boost::replace_all_copy(log, " ", "\\ ");
        status = posix_spawn_file_actions_addopen(&action, 1, out.c_str(), O_CREAT | O_APPEND | O_WRONLY, 0644);
        if (status)
            throw std::runtime_error(utils::format("posix_spawn_file_actions_addopen: error=%d", status));

        status = posix_spawn_file_actions_adddup2(&action, 1, 2);
        if (status)
            throw std::runtime_error(utils::format("posix_spawn_file_actions_adddup2: error=%d", status));
    }

    posix_spawnattr_t attr;
    status = posix_spawnattr_init(&attr);
    if (status)
        throw std::runtime_error(utils::format("posix_spawnattr_init: error=%d", status));

    status = posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSID);
    if (status)
        throw std::runtime_error(utils::format("posix_spawnattr_setflags: error=%d", status));

    pid_t pid;
    status = posix_spawnp(&pid, exe.data(), &action, &attr, argv.data(), environ);
    if (status)
        throw std::runtime_error(utils::format("posix_spawn: error=%d", status));

    _inf_ << "execute: pid=" << pid;

    status = posix_spawn_file_actions_destroy(&action);
    if (status)
        throw std::runtime_error(utils::format("posix_spawn_file_actions_destroy: error=%d", status));

    status = posix_spawnattr_destroy(&attr);
    if (status)
        throw std::runtime_error(utils::format("posix_spawnattr_destroy: error=%d", status));

    if (wait)
    {
        int code = 0;
        if (waitpid(pid, &code, 0) == -1)
        {
            if (errno != ECHILD)
                throw std::runtime_error(utils::format("waitpid: error=%d", errno));
        }
        else if (code)
            throw std::runtime_error(utils::format("execute: error=%d", code));
    }
}

}

#endif
