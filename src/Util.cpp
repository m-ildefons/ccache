// Copyright (C) 2019-2022 Joel Rosdahl and other contributors
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

#include "Util.hpp"

#include "Config.hpp"
#include "Context.hpp"
#include "Fd.hpp"
#include "Logging.hpp"
#include "TemporaryFile.hpp"
#include "Win32Util.hpp"

#include <Config.hpp>
#include <Finalizer.hpp>
#include <core/exceptions.hpp>
#include <core/wincompat.hpp>
#include <fmtmacros.hpp>
#include <util/TimePoint.hpp>
#include <util/file.hpp>
#include <util/path.hpp>
#include <util/string.hpp>

#include <limits.h> // NOLINT: PATH_MAX is defined in limits.h

extern "C" {
#include "third_party/base32hex.h"
}

#ifdef HAVE_DIRENT_H
#  include <dirent.h>
#endif

#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif

#include <fcntl.h>

#ifdef HAVE_PWD_H
#  include <pwd.h>
#endif

#ifdef __linux__
#  ifdef HAVE_SYS_IOCTL_H
#    include <sys/ioctl.h>
#  endif
#  ifdef HAVE_LINUX_FS_H
#    include <linux/fs.h>
#    ifndef FICLONE
#      define FICLONE _IOW(0x94, 9, int)
#    endif
#    define FILE_CLONING_SUPPORTED 1
#  endif
#endif

#ifdef __APPLE__
#  ifdef HAVE_SYS_CLONEFILE_H
#    include <sys/clonefile.h>
#    ifdef CLONE_NOOWNERCOPY
#      define FILE_CLONING_SUPPORTED 1
#    endif
#  endif
#endif

using IncludeDelimiter = util::Tokenizer::IncludeDelimiter;

namespace {

// Process umask, read and written by get_umask and set_umask.
mode_t g_umask = [] {
  const mode_t mask = umask(0);
  umask(mask);
  return mask;
}();

// Search for the first match of the following regular expression:
//
//   \x1b\[[\x30-\x3f]*[\x20-\x2f]*[Km]
//
// The primary reason for not using std::regex is that it's not available for
// GCC 4.8. It's also a bit bloated. The reason for not using POSIX regex
// functionality is that it's are not available in MinGW.
std::string_view
find_first_ansi_csi_seq(std::string_view string)
{
  size_t pos = 0;
  while (pos < string.length() && string[pos] != 0x1b) {
    ++pos;
  }
  if (pos + 1 >= string.length() || string[pos + 1] != '[') {
    return {};
  }
  size_t start = pos;
  pos += 2;
  while (pos < string.length()
         && (string[pos] >= 0x30 && string[pos] <= 0x3f)) {
    ++pos;
  }
  while (pos < string.length()
         && (string[pos] >= 0x20 && string[pos] <= 0x2f)) {
    ++pos;
  }
  if (pos < string.length() && (string[pos] == 'K' || string[pos] == 'm')) {
    return string.substr(start, pos + 1 - start);
  } else {
    return {};
  }
}

size_t
path_max(const std::string& path)
{
#ifdef PATH_MAX
  (void)path;
  return PATH_MAX;
#elif defined(MAXPATHLEN)
  (void)path;
  return MAXPATHLEN;
#elif defined(_PC_PATH_MAX)
  long maxlen = pathconf(path.c_str(), _PC_PATH_MAX);
  return maxlen >= 4096 ? maxlen : 4096;
#endif
}

template<typename T>
std::vector<T>
split_into(std::string_view string,
           const char* separators,
           util::Tokenizer::Mode mode,
           IncludeDelimiter include_delimiter)

{
  std::vector<T> result;
  for (const auto token :
       util::Tokenizer(string, separators, mode, include_delimiter)) {
    result.emplace_back(token);
  }
  return result;
}

std::string
rewrite_stderr_to_absolute_paths(std::string_view text)
{
  static const std::string in_file_included_from = "In file included from ";

  std::string result;
  using util::Tokenizer;
  for (auto line : Tokenizer(text,
                             "\n",
                             Tokenizer::Mode::include_empty,
                             Tokenizer::IncludeDelimiter::yes)) {
    // Rewrite <path> to <absolute path> in the following two cases, where X may
    // be optional ANSI CSI sequences:
    //
    // In file included from X<path>X:1:
    // X<path>X:1:2: ...

    if (util::starts_with(line, in_file_included_from)) {
      result += in_file_included_from;
      line = line.substr(in_file_included_from.length());
    }
    while (!line.empty() && line[0] == 0x1b) {
      auto csi_seq = find_first_ansi_csi_seq(line);
      result.append(csi_seq.data(), csi_seq.length());
      line = line.substr(csi_seq.length());
    }
    size_t path_end = line.find(':');
    if (path_end == std::string_view::npos) {
      result.append(line.data(), line.length());
    } else {
      std::string path(line.substr(0, path_end));
      if (Stat::stat(path)) {
        result += Util::real_path(path);
        auto tail = line.substr(path_end);
        result.append(tail.data(), tail.length());
      } else {
        result.append(line.data(), line.length());
      }
    }
  }
  return result;
}

} // namespace

namespace Util {

std::string_view
base_name(std::string_view path)
{
#ifdef _WIN32
  const char delim[] = "/\\";
#else
  const char delim[] = "/";
#endif
  size_t n = path.find_last_of(delim);
  return n == std::string::npos ? path : path.substr(n + 1);
}

std::string
change_extension(std::string_view path, std::string_view new_ext)
{
  std::string_view without_ext = Util::remove_extension(path);
  return std::string(without_ext).append(new_ext.data(), new_ext.length());
}

#ifdef FILE_CLONING_SUPPORTED
void
clone_file(const std::string& src, const std::string& dest, bool via_tmp_file)
{
#  if defined(__linux__)
  Fd src_fd(open(src.c_str(), O_RDONLY));
  if (!src_fd) {
    throw core::Error(FMT("{}: {}", src, strerror(errno)));
  }

  Fd dest_fd;
  std::string tmp_file;
  if (via_tmp_file) {
    TemporaryFile temp_file(dest);
    dest_fd = std::move(temp_file.fd);
    tmp_file = temp_file.path;
  } else {
    dest_fd =
      Fd(open(dest.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0666));
    if (!dest_fd) {
      throw core::Error(FMT("{}: {}", src, strerror(errno)));
    }
  }

  if (ioctl(*dest_fd, FICLONE, *src_fd) != 0) {
    throw core::Error(strerror(errno));
  }

  dest_fd.close();
  src_fd.close();

  if (via_tmp_file) {
    Util::rename(tmp_file, dest);
  }
#  elif defined(__APPLE__)
  (void)via_tmp_file;
  if (clonefile(src.c_str(), dest.c_str(), CLONE_NOOWNERCOPY) != 0) {
    throw core::Error(strerror(errno));
  }
#  else
  (void)src;
  (void)dest;
  (void)via_tmp_file;
  throw core::Error(strerror(EOPNOTSUPP));
#  endif
}
#endif // FILE_CLONING_SUPPORTED

void
clone_hard_link_or_copy_file(const Config& config,
                             const std::string& source,
                             const std::string& dest,
                             bool via_tmp_file)
{
  if (config.file_clone()) {
#ifdef FILE_CLONING_SUPPORTED
    LOG("Cloning {} to {}", source, dest);
    try {
      clone_file(source, dest, via_tmp_file);
      return;
    } catch (core::Error& e) {
      LOG("Failed to clone: {}", e.what());
    }
#else
    LOG("Not cloning {} to {} since it's unsupported", source, dest);
#endif
  }
  if (config.hard_link()) {
    LOG("Hard linking {} to {}", source, dest);
    try {
      Util::hard_link(source, dest);
#ifndef _WIN32
      if (chmod(dest.c_str(), 0444 & ~Util::get_umask()) != 0) {
        LOG("Failed to chmod {}: {}", dest.c_str(), strerror(errno));
      }
#endif
      return;
    } catch (const core::Error& e) {
      LOG("Failed to hard link {} to {}: {}", source, dest, e.what());
      // Fall back to copying.
    }
  }

  LOG("Copying {} to {}", source, dest);
  copy_file(source, dest, via_tmp_file);
}

size_t
common_dir_prefix_length(std::string_view dir, std::string_view path)
{
  if (dir.empty() || path.empty() || dir == "/" || path == "/") {
    return 0;
  }

  ASSERT(dir[0] == '/');
  ASSERT(path[0] == '/');

  const size_t limit = std::min(dir.length(), path.length());
  size_t i = 0;

  while (i < limit && dir[i] == path[i]) {
    ++i;
  }

  if ((i == dir.length() && i == path.length())
      || (i == dir.length() && path[i] == '/')
      || (i == path.length() && dir[i] == '/')) {
    return i;
  }

  do {
    --i;
  } while (i > 0 && dir[i] != '/' && path[i] != '/');

  return i;
}

void
copy_fd(int fd_in, int fd_out)
{
  util::read_fd(fd_in, [=](const void* data, size_t size) {
    util::write_fd(fd_out, data, size);
  });
}

void
copy_file(const std::string& src, const std::string& dest, bool via_tmp_file)
{
  Fd src_fd(open(src.c_str(), O_RDONLY | O_BINARY));
  if (!src_fd) {
    throw core::Error(
      FMT("Failed to open {} for reading: {}", src, strerror(errno)));
  }

  unlink(dest.c_str());

  Fd dest_fd;
  std::string tmp_file;
  if (via_tmp_file) {
    TemporaryFile temp_file(dest);
    dest_fd = std::move(temp_file.fd);
    tmp_file = temp_file.path;
  } else {
    dest_fd =
      Fd(open(dest.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0666));
    if (!dest_fd) {
      throw core::Error(
        FMT("Failed to open {} for writing: {}", dest, strerror(errno)));
    }
  }

  copy_fd(*src_fd, *dest_fd);
  dest_fd.close();
  src_fd.close();

  if (via_tmp_file) {
    Util::rename(tmp_file, dest);
  }
}

bool
create_dir(std::string_view dir)
{
  std::string dir_str(dir);
  auto st = Stat::stat(dir_str);
  if (st) {
    if (st.is_directory()) {
      return true;
    } else {
      errno = ENOTDIR;
      return false;
    }
  } else {
    if (!create_dir(Util::dir_name(dir))) {
      return false;
    }
    int result = mkdir(dir_str.c_str(), 0777);
    // Treat an already existing directory as OK since the file system could
    // have changed in between calling stat and actually creating the
    // directory. This can happen when there are multiple instances of ccache
    // running and trying to create the same directory chain, which usually is
    // the case when the cache root does not initially exist. As long as one of
    // the processes creates the directories then our condition is satisfied
    // and we avoid a race condition.
    return result == 0 || errno == EEXIST;
  }
}

std::string_view
dir_name(std::string_view path)
{
#ifdef _WIN32
  const char delim[] = "/\\";
#else
  const char delim[] = "/";
#endif
  size_t n = path.find_last_of(delim);
  if (n == std::string::npos) {
    // "foo" -> "."
    return ".";
  } else if (n == 0) {
    // "/" -> "/" (Windows: or "\\" -> "\\")
    return path.substr(0, 1);
#ifdef _WIN32
  } else if (n == 2 && path[1] == ':') {
    // Windows: "C:\\foo" -> "C:\\" or "C:/foo" -> "C:/"
    return path.substr(0, 3);
#endif
  } else {
    // "/dir/foo" -> "/dir" (Windows: or "C:\\dir\\foo" -> "C:\\dir")
    return path.substr(0, n);
  }
}

std::string
expand_environment_variables(const std::string& str)
{
  std::string result;
  const char* left = str.c_str();
  const char* right = left;
  while (*right) {
    if (*right == '$') {
      result.append(left, right - left);

      left = right + 1;
      bool curly = *left == '{';
      if (curly) {
        ++left;
      }
      right = left;
      while (isalnum(*right) || *right == '_') {
        ++right;
      }
      if (curly && *right != '}') {
        throw core::Error(FMT("syntax error: missing '}}' after \"{}\"", left));
      }
      if (right == left) {
        // Special case: don't consider a single $ the left of a variable.
        result += '$';
        --right;
      } else {
        std::string name(left, right - left);
        const char* value = getenv(name.c_str());
        if (!value) {
          throw core::Error(FMT("environment variable \"{}\" not set", name));
        }
        result += value;
        if (!curly) {
          --right;
        }
        left = right + 1;
      }
    }
    ++right;
  }
  result += left;
  return result;
}

int
fallocate(int fd, long new_size)
{
#ifdef HAVE_POSIX_FALLOCATE
  const int posix_fallocate_err = posix_fallocate(fd, 0, new_size);
  if (posix_fallocate_err == 0 || posix_fallocate_err != EINVAL) {
    return posix_fallocate_err;
  }
  // the underlying filesystem does not support the operation so fallback to
  // lseeks
#endif
  off_t saved_pos = lseek(fd, 0, SEEK_END);
  off_t old_size = lseek(fd, 0, SEEK_END);
  if (old_size == -1) {
    int err = errno;
    lseek(fd, saved_pos, SEEK_SET);
    return err;
  }
  if (old_size >= new_size) {
    lseek(fd, saved_pos, SEEK_SET);
    return 0;
  }
  long bytes_to_write = new_size - old_size;
  void* buf = calloc(bytes_to_write, 1);
  if (!buf) {
    lseek(fd, saved_pos, SEEK_SET);
    return ENOMEM;
  }
  int err = 0;
  try {
    util::write_fd(fd, buf, bytes_to_write);
  } catch (core::Error&) {
    err = errno;
  }
  lseek(fd, saved_pos, SEEK_SET);
  free(buf);
  return err;
}

std::string
format_argv_for_logging(const char* const* argv)
{
  std::string result;
  for (size_t i = 0; argv[i]; ++i) {
    if (i != 0) {
      result += ' ';
    }
    for (const char* arg = argv[i]; *arg; ++arg) {
      result += *arg;
    }
  }
  return result;
}

std::string
format_base16(const uint8_t* data, size_t size)
{
  static const char digits[] = "0123456789abcdef";
  std::string result;
  result.resize(2 * size);
  for (size_t i = 0; i < size; ++i) {
    result[i * 2] = digits[data[i] >> 4];
    result[i * 2 + 1] = digits[data[i] & 0xF];
  }
  return result;
}

std::string
format_base32hex(const uint8_t* data, size_t size)
{
  const size_t bytes_to_reserve = size * 8 / 5 + 1;
  std::string result(bytes_to_reserve, 0);
  const size_t actual_size = base32hex(&result[0], data, size);
  result.resize(actual_size);
  return result;
}

std::string
format_human_readable_diff(int64_t diff)
{
  const char* sign = diff == 0 ? "" : (diff > 0 ? "+" : "-");
  return FMT("{}{}", sign, format_human_readable_size(std::abs(diff)));
}

std::string
format_human_readable_size(uint64_t size)
{
  if (size >= 1000 * 1000 * 1000) {
    return FMT("{:.1f} GB", size / ((double)(1000 * 1000 * 1000)));
  } else if (size >= 1000 * 1000) {
    return FMT("{:.1f} MB", size / ((double)(1000 * 1000)));
  } else if (size >= 1000) {
    return FMT("{:.1f} kB", size / 1000.0);
  } else if (size == 1) {
    return "1 byte";
  } else {
    return FMT("{} bytes", size);
  }
}

std::string
format_parsable_size_with_suffix(uint64_t size)
{
  if (size >= 1000 * 1000 * 1000) {
    return FMT("{:.1f}G", size / ((double)(1000 * 1000 * 1000)));
  } else if (size >= 1000 * 1000) {
    return FMT("{:.1f}M", size / ((double)(1000 * 1000)));
  } else {
    return FMT("{}", size);
  }
}

void
ensure_dir_exists(std::string_view dir)
{
  if (!create_dir(dir)) {
    throw core::Fatal(
      FMT("Failed to create directory {}: {}", dir, strerror(errno)));
  }
}

std::string
get_actual_cwd()
{
  char buffer[PATH_MAX];
  if (getcwd(buffer, sizeof(buffer))) {
#ifndef _WIN32
    return buffer;
#else
    std::string cwd = buffer;
    std::replace(cwd.begin(), cwd.end(), '\\', '/');
    return cwd;
#endif
  } else {
    return {};
  }
}

std::string
get_apparent_cwd(const std::string& actual_cwd)
{
#ifdef _WIN32
  return actual_cwd;
#else
  auto pwd = getenv("PWD");
  if (!pwd || !util::is_absolute_path(pwd)) {
    return actual_cwd;
  }

  auto pwd_stat = Stat::stat(pwd);
  auto cwd_stat = Stat::stat(actual_cwd);
  return !pwd_stat || !cwd_stat || !pwd_stat.same_inode_as(cwd_stat)
           ? actual_cwd
           : normalize_concrete_absolute_path(pwd);
#endif
}

std::string_view
get_extension(std::string_view path)
{
#ifndef _WIN32
  const char stop_at_chars[] = "./";
#else
  const char stop_at_chars[] = "./\\";
#endif
  size_t pos = path.find_last_of(stop_at_chars);
  if (pos == std::string_view::npos || path.at(pos) == '/') {
    return {};
#ifdef _WIN32
  } else if (path.at(pos) == '\\') {
    return {};
#endif
  } else {
    return path.substr(pos);
  }
}

std::string
get_home_directory()
{
#ifdef _WIN32
  if (const char* p = getenv("USERPROFILE")) {
    return p;
  }
  throw core::Fatal(
    "The USERPROFILE environment variable must be set to your user profile "
    "folder");
#else
  if (const char* p = getenv("HOME")) {
    return p;
  }
#  ifdef HAVE_GETPWUID
  {
    struct passwd* pwd = getpwuid(getuid());
    if (pwd) {
      return pwd->pw_dir;
    }
  }
#  endif
  throw core::Fatal(
    "Could not determine home directory from $HOME or getpwuid(3)");
#endif
}

const char*
get_hostname()
{
  static char hostname[260] = "";

  if (hostname[0]) {
    return hostname;
  }

  if (gethostname(hostname, sizeof(hostname)) != 0) {
    strcpy(hostname, "unknown");
  }
  hostname[sizeof(hostname) - 1] = 0;
  return hostname;
}

std::string
get_relative_path(std::string_view dir, std::string_view path)
{
  ASSERT(util::is_absolute_path(dir));
  ASSERT(util::is_absolute_path(path));

#ifdef _WIN32
  // Paths can be escaped by a slash for use with e.g. -isystem.
  if (dir.length() >= 3 && dir[0] == '/' && dir[2] == ':') {
    dir = dir.substr(1);
  }
  if (path.length() >= 3 && path[0] == '/' && path[2] == ':') {
    path = path.substr(1);
  }
  if (dir[0] != path[0]) {
    // Drive letters differ.
    return std::string(path);
  }
  dir = dir.substr(2);
  path = path.substr(2);
#endif

  std::string result;
  size_t common_prefix_len = Util::common_dir_prefix_length(dir, path);
  if (common_prefix_len > 0 || dir != "/") {
    for (size_t i = common_prefix_len; i < dir.length(); ++i) {
      if (dir[i] == '/') {
        if (!result.empty()) {
          result += '/';
        }
        result += "..";
      }
    }
  }
  if (path.length() > common_prefix_len) {
    if (!result.empty()) {
      result += '/';
    }
    result += std::string(path.substr(common_prefix_len + 1));
  }
  result.erase(result.find_last_not_of('/') + 1);
  return result.empty() ? "." : result;
}

mode_t
get_umask()
{
  return g_umask;
}

void
hard_link(const std::string& oldpath, const std::string& newpath)
{
  // Assumption: newpath may already exist as a left-over file from a previous
  // run, but it's only we who can create the file entry now so we don't try to
  // handle a race between unlink() and link() below.
  unlink(newpath.c_str());

#ifndef _WIN32
  if (link(oldpath.c_str(), newpath.c_str()) != 0) {
    throw core::Error(strerror(errno));
  }
#else
  if (!CreateHardLink(newpath.c_str(), oldpath.c_str(), nullptr)) {
    throw core::Error(Win32Util::error_message(GetLastError()));
  }
#endif
}

std::optional<size_t>
is_absolute_path_with_prefix(std::string_view path)
{
#ifdef _WIN32
  const char delim[] = "/\\";
#else
  const char delim[] = "/";
#endif
  auto split_pos = path.find_first_of(delim);
  if (split_pos != std::string::npos) {
#ifdef _WIN32
    // -I/C:/foo and -I/c/foo will already be handled by delim_pos correctly
    // resulting in -I and /C:/foo or /c/foo respectively. -IC:/foo will not as
    // we would get -IC: and /foo.
    if (split_pos > 0 && path[split_pos - 1] == ':') {
      split_pos = split_pos - 2;
    }
#endif
    // This is not redundant on some platforms, so nothing to simplify.
    // NOLINTNEXTLINE(readability-simplify-boolean-expr)
    return split_pos;
  }
  return std::nullopt;
}

bool
is_ccache_executable(const std::string_view path)
{
  std::string name(Util::base_name(path));
#ifdef _WIN32
  name = Util::to_lowercase(name);
#endif
  return util::starts_with(name, "ccache");
}

bool
is_precompiled_header(std::string_view path)
{
  std::string_view ext = get_extension(path);
  return ext == ".gch" || ext == ".pch" || ext == ".pth"
         || get_extension(dir_name(path)) == ".gch";
}

std::optional<tm>
localtime(std::optional<util::TimePoint> time)
{
  time_t timestamp = time ? time->sec() : util::TimePoint::now().sec();
  tm result;
  if (localtime_r(&timestamp, &result)) {
    return result;
  } else {
    return std::nullopt;
  }
}

std::string
make_relative_path(const std::string& base_dir,
                   const std::string& actual_cwd,
                   const std::string& apparent_cwd,
                   std::string_view path)
{
  if (base_dir.empty() || !util::path_starts_with(path, base_dir)) {
    return std::string(path);
  }

#ifdef _WIN32
  std::string winpath;
  if (path.length() >= 3 && path[0] == '/') {
    if (isalpha(path[1]) && path[2] == '/') {
      // Transform /c/path... to c:/path...
      winpath = FMT("{}:/{}", path[1], path.substr(3));
      path = winpath;
    } else if (path[2] == ':') {
      // Transform /c:/path to c:/path
      winpath = std::string(path.substr(1));
      path = winpath;
    }
  }
#endif

  // The algorithm for computing relative paths below only works for existing
  // paths. If the path doesn't exist, find the first ancestor directory that
  // does exist and assemble the path again afterwards.

  std::vector<std::string> relpath_candidates;
  const auto original_path = path;
  Stat path_stat;
  while (!(path_stat = Stat::stat(std::string(path)))) {
    path = Util::dir_name(path);
  }
  const auto path_suffix = std::string(original_path.substr(path.length()));
  const auto real_path = Util::real_path(std::string(path));

  const auto add_relpath_candidates = [&](auto path) {
    const std::string normalized_path =
      Util::normalize_abstract_absolute_path(path);
    relpath_candidates.push_back(
      Util::get_relative_path(actual_cwd, normalized_path));
    if (apparent_cwd != actual_cwd) {
      relpath_candidates.emplace_back(
        Util::get_relative_path(apparent_cwd, normalized_path));
    }
  };
  add_relpath_candidates(path);
  if (real_path != path) {
    add_relpath_candidates(real_path);
  }

  // Find best (i.e. shortest existing) match:
  std::sort(relpath_candidates.begin(),
            relpath_candidates.end(),
            [](const auto& path1, const auto& path2) {
              return path1.length() < path2.length();
            });
  for (const auto& relpath : relpath_candidates) {
    if (Stat::stat(relpath).same_inode_as(path_stat)) {
      return relpath + path_suffix;
    }
  }

  // No match so nothing else to do than to return the unmodified path.
  return std::string(original_path);
}

std::string
make_relative_path(const Context& ctx, std::string_view path)
{
  return make_relative_path(
    ctx.config.base_dir(), ctx.actual_cwd, ctx.apparent_cwd, path);
}

bool
matches_dir_prefix_or_file(std::string_view dir_prefix_or_file,
                           std::string_view path)
{
  return !dir_prefix_or_file.empty() && !path.empty()
         && dir_prefix_or_file.length() <= path.length()
         && util::starts_with(path, dir_prefix_or_file)
         && (dir_prefix_or_file.length() == path.length()
             || is_dir_separator(path[dir_prefix_or_file.length()])
             || is_dir_separator(dir_prefix_or_file.back()));
}

std::string
normalize_abstract_absolute_path(std::string_view path)
{
  if (!util::is_absolute_path(path)) {
    return std::string(path);
  }

#ifdef _WIN32
  if (path.find("\\") != std::string_view::npos) {
    std::string new_path(path);
    std::replace(new_path.begin(), new_path.end(), '\\', '/');
    return normalize_abstract_absolute_path(new_path);
  }

  std::string drive(path.substr(0, 2));
  path = path.substr(2);
#endif

  std::string result = "/";
  const size_t npos = std::string_view::npos;
  size_t left = 1;

  while (true) {
    if (left >= path.length()) {
      break;
    }
    const auto right = path.find('/', left);
    std::string_view part =
      path.substr(left, right == npos ? npos : right - left);
    if (part == "..") {
      if (result.length() > 1) {
        // "/x/../part" -> "/part"
        result.erase(result.rfind('/', result.length() - 2) + 1);
      } else {
        // "/../part" -> "/part"
      }
    } else if (part == ".") {
      // "/x/." -> "/x"
    } else {
      result.append(part.begin(), part.end());
      if (result[result.length() - 1] != '/') {
        result += '/';
      }
    }
    if (right == npos) {
      break;
    }
    left = right + 1;
  }
  if (result.length() > 1) {
    result.erase(result.find_last_not_of('/') + 1);
  }

#ifdef _WIN32
  return drive + result;
#else
  return result;
#endif
}

std::string
normalize_concrete_absolute_path(const std::string& path)
{
  const auto normalized_path = normalize_abstract_absolute_path(path);
  return Stat::stat(normalized_path).same_inode_as(Stat::stat(path))
           ? normalized_path
           : path;
}

uint64_t
parse_duration(std::string_view duration)
{
  uint64_t factor = 0;
  char last_ch = duration.empty() ? '\0' : duration[duration.length() - 1];

  switch (last_ch) {
  case 'd':
    factor = 24 * 60 * 60;
    break;
  case 's':
    factor = 1;
    break;
  default:
    throw core::Error(FMT(
      "invalid suffix (supported: d (day) and s (second)): \"{}\"", duration));
  }

  const auto value =
    util::parse_unsigned(duration.substr(0, duration.length() - 1));
  if (value) {
    return factor * *value;
  } else {
    throw core::Error(value.error());
  }
}

uint64_t
parse_size(const std::string& value)
{
  errno = 0;

  char* p;
  double result = strtod(value.c_str(), &p);
  if (errno != 0 || result < 0 || p == value.c_str() || value.empty()) {
    throw core::Error(FMT("invalid size: \"{}\"", value));
  }

  while (isspace(*p)) {
    ++p;
  }

  if (*p != '\0') {
    unsigned multiplier = *(p + 1) == 'i' ? 1024 : 1000;
    switch (*p) {
    case 'T':
      result *= multiplier;
      [[fallthrough]];
    case 'G':
      result *= multiplier;
      [[fallthrough]];
    case 'M':
      result *= multiplier;
      [[fallthrough]];
    case 'K':
    case 'k':
      result *= multiplier;
      break;
    default:
      throw core::Error(FMT("invalid size: \"{}\"", value));
    }
  } else {
    // Default suffix: G.
    result *= 1000 * 1000 * 1000;
  }
  return static_cast<uint64_t>(result);
}

#ifndef _WIN32
std::string
read_link(const std::string& path)
{
  size_t buffer_size = path_max(path);
  std::unique_ptr<char[]> buffer(new char[buffer_size]);
  const auto len = readlink(path.c_str(), buffer.get(), buffer_size - 1);
  if (len == -1) {
    return "";
  }
  buffer[len] = 0;
  return buffer.get();
}
#endif

std::string
real_path(const std::string& path, bool return_empty_on_error)
{
  size_t buffer_size = path_max(path);
  std::unique_ptr<char[]> managed_buffer(new char[buffer_size]);
  char* buffer = managed_buffer.get();
  char* resolved = nullptr;

#ifdef HAVE_REALPATH
  resolved = realpath(path.c_str(), buffer);
#elif defined(_WIN32)
  const char* c_path = path.c_str();
  if (c_path[0] == '/') {
    c_path++; // Skip leading slash.
  }
  HANDLE path_handle = CreateFile(c_path,
                                  GENERIC_READ,
                                  FILE_SHARE_READ,
                                  nullptr,
                                  OPEN_EXISTING,
                                  FILE_ATTRIBUTE_NORMAL,
                                  nullptr);
  if (INVALID_HANDLE_VALUE != path_handle) {
    bool ok = GetFinalPathNameByHandle(
      path_handle, buffer, buffer_size, FILE_NAME_NORMALIZED);
    CloseHandle(path_handle);
    if (!ok) {
      return path;
    }
    resolved = buffer + 4; // Strip \\?\ from the file name.
  } else {
    snprintf(buffer, buffer_size, "%s", c_path);
    resolved = buffer;
  }
#else
#  error No realpath function available
#endif

  return resolved ? resolved : (return_empty_on_error ? "" : path);
}

std::string_view
remove_extension(std::string_view path)
{
  return path.substr(0, path.length() - get_extension(path).length());
}

void
rename(const std::string& oldpath, const std::string& newpath)
{
#ifndef _WIN32
  if (::rename(oldpath.c_str(), newpath.c_str()) != 0) {
    throw core::Error(
      FMT("failed to rename {} to {}: {}", oldpath, newpath, strerror(errno)));
  }
#else
  // Windows' rename() won't overwrite an existing file, so need to use
  // MoveFileEx instead.
  if (!MoveFileExA(
        oldpath.c_str(), newpath.c_str(), MOVEFILE_REPLACE_EXISTING)) {
    DWORD error = GetLastError();
    throw core::Error(FMT("failed to rename {} to {}: {}",
                          oldpath,
                          newpath,
                          Win32Util::error_message(error)));
  }
#endif
}

void
send_to_fd(const Context& ctx, std::string_view text, int fd)
{
  std::string_view text_to_send = text;
  std::string modified_text;

#ifdef _WIN32
  // stdout/stderr are normally opened in text mode, which would convert
  // newlines a second time since we treat output as binary data. Make sure to
  // switch to binary mode.
  int oldmode = _setmode(fd, _O_BINARY);
  Finalizer binary_mode_restorer([=] { _setmode(fd, oldmode); });
#endif

  if (ctx.args_info.strip_diagnostics_colors) {
    try {
      modified_text = strip_ansi_csi_seqs(text);
      text_to_send = modified_text;
    } catch (const core::Error&) {
      // Ignore.
    }
  }

  if (ctx.config.absolute_paths_in_stderr()) {
    modified_text = rewrite_stderr_to_absolute_paths(text_to_send);
    text_to_send = modified_text;
  }

  const auto result =
    util::write_fd(fd, text_to_send.data(), text_to_send.length());
  if (!result) {
    throw core::Error(FMT("Failed to write to {}: {}", fd, result.error()));
  }
}

void
set_cloexec_flag(int fd)
{
#ifndef _WIN32
  int flags = fcntl(fd, F_GETFD, 0);
  if (flags >= 0) {
    fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
  }
#else
  (void)fd;
#endif
}

mode_t
set_umask(mode_t mask)
{
  g_umask = mask;
  return umask(mask);
}

void
setenv(const std::string& name, const std::string& value)
{
#ifdef HAVE_SETENV
  ::setenv(name.c_str(), value.c_str(), true);
#else
  char* string;
  asprintf(&string, "%s=%s", name.c_str(), value.c_str());
  putenv(string); // Leak to environment.
#endif
}

std::vector<std::string_view>
split_into_views(std::string_view string,
                 const char* separators,
                 util::Tokenizer::Mode mode,
                 IncludeDelimiter include_delimiter)
{
  return split_into<std::string_view>(
    string, separators, mode, include_delimiter);
}

std::vector<std::string>
split_into_strings(std::string_view string,
                   const char* separators,
                   util::Tokenizer::Mode mode,
                   IncludeDelimiter include_delimiter)
{
  return split_into<std::string>(string, separators, mode, include_delimiter);
}

std::string
strip_ansi_csi_seqs(std::string_view string)
{
  size_t pos = 0;
  std::string result;

  while (true) {
    auto seq_span = find_first_ansi_csi_seq(string.substr(pos));
    auto data_start = string.data() + pos;
    auto data_length =
      seq_span.empty() ? string.length() - pos : seq_span.data() - data_start;
    result.append(data_start, data_length);
    if (seq_span.empty()) {
      // Reached tail.
      break;
    }
    pos += data_length + seq_span.length();
  }

  return result;
}

std::string
to_lowercase(std::string_view string)
{
  std::string result;
  result.resize(string.length());
  std::transform(string.begin(), string.end(), result.begin(), tolower);
  return result;
}

#ifdef HAVE_DIRENT_H

void
traverse(const std::string& path, const TraverseVisitor& visitor)
{
  DIR* dir = opendir(path.c_str());
  if (dir) {
    struct dirent* entry;
    while ((entry = readdir(dir))) {
      if (strcmp(entry->d_name, "") == 0 || strcmp(entry->d_name, ".") == 0
          || strcmp(entry->d_name, "..") == 0) {
        continue;
      }

      std::string entry_path = path + "/" + entry->d_name;
      bool is_dir;
#  ifdef _DIRENT_HAVE_D_TYPE
      if (entry->d_type != DT_UNKNOWN) {
        is_dir = entry->d_type == DT_DIR;
      } else
#  endif
      {
        auto stat = Stat::lstat(entry_path);
        if (!stat) {
          if (stat.error_number() == ENOENT || stat.error_number() == ESTALE) {
            continue;
          }
          throw core::Error(FMT("failed to lstat {}: {}",
                                entry_path,
                                strerror(stat.error_number())));
        }
        is_dir = stat.is_directory();
      }
      if (is_dir) {
        traverse(entry_path, visitor);
      } else {
        visitor(entry_path, false);
      }
    }
    closedir(dir);
    visitor(path, true);
  } else if (errno == ENOTDIR) {
    visitor(path, false);
  } else {
    throw core::Error(
      FMT("failed to open directory {}: {}", path, strerror(errno)));
  }
}

#else // If not available, use the C++17 std::filesystem implementation.

void
traverse(const std::string& path, const TraverseVisitor& visitor)
{
  if (std::filesystem::is_directory(path)) {
    for (auto&& p : std::filesystem::directory_iterator(path)) {
      std::string entry = p.path().string();

      if (p.is_directory()) {
        traverse(entry, visitor);
      } else {
        visitor(entry, false);
      }
    }
    visitor(path, true);
  } else if (std::filesystem::exists(path)) {
    visitor(path, false);
  } else {
    throw core::Error(
      FMT("failed to open directory {}: {}", path, strerror(errno)));
  }
}

#endif

bool
unlink_safe(const std::string& path, UnlinkLog unlink_log)
{
  int saved_errno = 0;

  // If path is on an NFS share, unlink isn't atomic, so we rename to a temp
  // file. We don't care if the temp file is trashed, so it's always safe to
  // unlink it first.
  const std::string tmp_name =
    FMT("{}.ccache{}unlink", path, TemporaryFile::tmp_file_infix);

  bool success = true;
  try {
    Util::rename(path, tmp_name);
  } catch (core::Error&) {
    success = false;
    saved_errno = errno;
  }
  if (success && unlink(tmp_name.c_str()) != 0) {
    // It's OK if it was unlinked in a race.
    if (errno != ENOENT && errno != ESTALE) {
      success = false;
      saved_errno = errno;
    }
  }
  if (success || unlink_log == UnlinkLog::log_failure) {
    LOG("Unlink {} via {}", path, tmp_name);
    if (!success) {
      LOG("Unlink failed: {}", strerror(saved_errno));
    }
  }

  errno = saved_errno;
  return success;
}

bool
unlink_tmp(const std::string& path, UnlinkLog unlink_log)
{
  int saved_errno = 0;

  bool success =
    unlink(path.c_str()) == 0 || (errno == ENOENT || errno == ESTALE);
  saved_errno = errno;
  if (success || unlink_log == UnlinkLog::log_failure) {
    LOG("Unlink {}", path);
    if (!success) {
      LOG("Unlink failed: {}", strerror(saved_errno));
    }
  }

  errno = saved_errno;
  return success;
}

void
unsetenv(const std::string& name)
{
#ifdef HAVE_UNSETENV
  ::unsetenv(name.c_str());
#elif defined(_WIN32)
  SetEnvironmentVariable(name.c_str(), NULL);
#else
  putenv(strdup(name.c_str())); // Leak to environment.
#endif
}

void
wipe_path(const std::string& path)
{
  if (!Stat::lstat(path)) {
    return;
  }
  traverse(path, [](const std::string& p, bool is_dir) {
    if (is_dir) {
      if (rmdir(p.c_str()) != 0 && errno != ENOENT && errno != ESTALE) {
        throw core::Error(FMT("failed to rmdir {}: {}", p, strerror(errno)));
      }
    } else if (unlink(p.c_str()) != 0 && errno != ENOENT && errno != ESTALE) {
      throw core::Error(FMT("failed to unlink {}: {}", p, strerror(errno)));
    }
  });
}

} // namespace Util
