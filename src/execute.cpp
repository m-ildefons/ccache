// Copyright (C) 2002 Andrew Tridgell
// Copyright (C) 2011-2022 Joel Rosdahl and other contributors
//
// See doc/AUTHORS.adoc for a complete list of contributors.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation; either version 3 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program; if not, write to the Free Software Foundation, Inc., 51
// Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#include "execute.hpp"

#include "Config.hpp"
#include "Context.hpp"
#include "Fd.hpp"
#include "Logging.hpp"
#include "SignalHandler.hpp"
#include "Stat.hpp"
#include "TemporaryFile.hpp"
#include "Util.hpp"
#include "Win32Util.hpp"

#include <core/exceptions.hpp>
#include <core/wincompat.hpp>
#include <fmtmacros.hpp>
#include <util/file.hpp>
#include <util/path.hpp>

#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif

#ifdef HAVE_SYS_WAIT_H
#  include <sys/wait.h>
#endif

#ifdef _WIN32
#  include "Finalizer.hpp"
#endif

#ifdef _WIN32
static int win32execute(const char* path,
                        const char* const* argv,
                        int doreturn,
                        int fd_stdout,
                        int fd_stderr,
                        const std::string& temp_dir);

int
execute(Context& ctx, const char* const* argv, Fd&& fd_out, Fd&& fd_err)
{
  return win32execute(argv[0],
                      argv,
                      1,
                      fd_out.release(),
                      fd_err.release(),
                      ctx.config.temporary_dir());
}

void
execute_noreturn(const char* const* argv, const std::string& temp_dir)
{
  win32execute(argv[0], argv, 0, -1, -1, temp_dir);
}

std::string
win32getshell(const std::string& path)
{
  const char* path_list = getenv("PATH");
  std::string sh;
  if (Util::to_lowercase(Util::get_extension(path)) == ".sh" && path_list) {
    sh = find_executable_in_path("sh.exe", path_list);
  }
  if (sh.empty() && getenv("CCACHE_DETECT_SHEBANG")) {
    // Detect shebang.
    File fp(path, "r");
    if (fp) {
      char buf[10] = {0};
      fgets(buf, sizeof(buf) - 1, fp.get());
      if (std::string(buf) == "#!/bin/sh" && path_list) {
        sh = find_executable_in_path("sh.exe", path_list);
      }
    }
  }

  return sh;
}

int
win32execute(const char* path,
             const char* const* argv,
             int doreturn,
             int fd_stdout,
             int fd_stderr,
             const std::string& temp_dir)
{
  PROCESS_INFORMATION pi;
  memset(&pi, 0x00, sizeof(pi));

  STARTUPINFO si;
  memset(&si, 0x00, sizeof(si));

  std::string sh = win32getshell(path);
  if (!sh.empty()) {
    path = sh.c_str();
  }

  si.cb = sizeof(STARTUPINFO);
  if (fd_stdout != -1) {
    si.hStdOutput = (HANDLE)_get_osfhandle(fd_stdout);
    si.hStdError = (HANDLE)_get_osfhandle(fd_stderr);
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.dwFlags = STARTF_USESTDHANDLES;
    if (si.hStdOutput == INVALID_HANDLE_VALUE
        || si.hStdError == INVALID_HANDLE_VALUE) {
      return -1;
    }
  } else {
    // Redirect subprocess stdout, stderr into current process.
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.dwFlags = STARTF_USESTDHANDLES;
    if (si.hStdOutput == INVALID_HANDLE_VALUE
        || si.hStdError == INVALID_HANDLE_VALUE) {
      return -1;
    }
  }

  std::string args = Win32Util::argv_to_string(argv, sh);
  std::string full_path = Win32Util::add_exe_suffix(path);
  std::string tmp_file_path;

  Finalizer tmp_file_remover([&tmp_file_path] {
    if (!tmp_file_path.empty()) {
      Util::unlink_tmp(tmp_file_path);
    }
  });

  if (args.length() > 8192) {
    TemporaryFile tmp_file(FMT("{}/cmd_args", temp_dir));
    args = Win32Util::argv_to_string(argv + 1, sh, true);
    util::write_fd(*tmp_file.fd, args.data(), args.length());
    args = FMT(R"("{}" "@{}")", full_path, tmp_file.path);
    tmp_file_path = tmp_file.path;
    LOG("Arguments from {}", tmp_file.path);
  }
  BOOL ret = CreateProcess(full_path.c_str(),
                           const_cast<char*>(args.c_str()),
                           nullptr,
                           nullptr,
                           1,
                           0,
                           nullptr,
                           nullptr,
                           &si,
                           &pi);
  if (fd_stdout != -1) {
    close(fd_stdout);
    close(fd_stderr);
  }
  if (ret == 0) {
    DWORD error = GetLastError();
    LOG("failed to execute {}: {} ({})",
        full_path,
        Win32Util::error_message(error),
        error);
    return -1;
  }
  WaitForSingleObject(pi.hProcess, INFINITE);

  DWORD exitcode;
  GetExitCodeProcess(pi.hProcess, &exitcode);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  if (!doreturn) {
    exit(exitcode);
  }
  return exitcode;
}

#else

// Execute a compiler backend, capturing all output to the given paths the full
// path to the compiler to run is in argv[0].
int
execute(Context& ctx, const char* const* argv, Fd&& fd_out, Fd&& fd_err)
{
  LOG("Executing {}", Util::format_argv_for_logging(argv));

  {
    SignalHandlerBlocker signal_handler_blocker;
    ctx.compiler_pid = fork();
  }

  if (ctx.compiler_pid == -1) {
    throw core::Fatal(FMT("Failed to fork: {}", strerror(errno)));
  }

  if (ctx.compiler_pid == 0) {
    // Child.
    dup2(*fd_out, STDOUT_FILENO);
    fd_out.close();
    dup2(*fd_err, STDERR_FILENO);
    fd_err.close();
    exit(execv(argv[0], const_cast<char* const*>(argv)));
  }

  fd_out.close();
  fd_err.close();

  int status;
  int result;

  while ((result = waitpid(ctx.compiler_pid, &status, 0)) != ctx.compiler_pid) {
    if (result == -1 && errno == EINTR) {
      continue;
    }
    throw core::Fatal(FMT("waitpid failed: {}", strerror(errno)));
  }

  {
    SignalHandlerBlocker signal_handler_blocker;
    ctx.compiler_pid = 0;
  }

  if (WEXITSTATUS(status) == 0 && WIFSIGNALED(status)) {
    return -1;
  }

  return WEXITSTATUS(status);
}

void
execute_noreturn(const char* const* argv, const std::string& /*temp_dir*/)
{
  execv(argv[0], const_cast<char* const*>(argv));
}
#endif

std::string
find_executable(const Context& ctx,
                const std::string& name,
                const std::string& exclude_path)
{
  if (util::is_absolute_path(name)) {
    return name;
  }

  std::string path_list = ctx.config.path();
  if (path_list.empty()) {
    path_list = getenv("PATH");
  }
  if (path_list.empty()) {
    LOG_RAW("No PATH variable");
    return {};
  }

  return find_executable_in_path(name, path_list, exclude_path);
}

std::string
find_executable_in_path(const std::string& name,
                        const std::string& path_list,
                        std::optional<std::string> exclude_path)
{
  if (path_list.empty()) {
    return {};
  }

  const auto real_exclude_path =
    exclude_path ? Util::real_path(*exclude_path) : "";

  // Search the path list looking for the first compiler of the right name that
  // isn't us.
  for (const std::string& dir : util::split_path_list(path_list)) {
    const std::vector<std::string> candidates = {
      FMT("{}/{}", dir, name),
#ifdef _WIN32
      FMT("{}/{}.exe", dir, name),
#endif
    };
    for (const auto& candidate : candidates) {
      // A valid candidate:
      //
      // 1. Must exist (e.g., should not be a broken symlink) and be an
      //    executable.
      // 2. Must not resolve to the same program as argv[0] (i.e.,
      //    exclude_path). This can happen if ccache is masquerading as the
      //    compiler (with or without using a symlink).
      // 3. As an extra safety measure: must not be a ccache executable after
      //    resolving symlinks. This can happen if the candidate compiler is a
      //    symlink to another ccache executable.
      const bool candidate_exists =
#ifdef _WIN32
        Stat::stat(candidate);
#else
        access(candidate.c_str(), X_OK) == 0;
#endif
      if (candidate_exists) {
        const auto real_candidate = Util::real_path(candidate);
        if ((real_exclude_path.empty() || real_candidate != real_exclude_path)
            && !Util::is_ccache_executable(real_candidate)) {
          return candidate;
        }
      }
    }
  }

  return {};
}
