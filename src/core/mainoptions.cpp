// Copyright (C) 2021-2022 Joel Rosdahl and other contributors
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

#include "mainoptions.hpp"

#include <Config.hpp>
#include <Fd.hpp>
#include <File.hpp>
#include <Hash.hpp>
#include <InodeCache.hpp>
#include <ProgressBar.hpp>
#include <TemporaryFile.hpp>
#include <ThreadPool.hpp>
#include <UmaskScope.hpp>
#include <ccache.hpp>
#include <core/CacheEntry.hpp>
#include <core/FileRecompressor.hpp>
#include <core/Manifest.hpp>
#include <core/Result.hpp>
#include <core/ResultExtractor.hpp>
#include <core/ResultInspector.hpp>
#include <core/Statistics.hpp>
#include <core/StatsLog.hpp>
#include <core/exceptions.hpp>
#include <fmtmacros.hpp>
#include <storage/Storage.hpp>
#include <storage/local/LocalStorage.hpp>
#include <util/TextTable.hpp>
#include <util/XXH3_128.hpp>
#include <util/expected.hpp>
#include <util/file.hpp>
#include <util/string.hpp>

#include <fcntl.h>

#include <algorithm>
#include <atomic>
#include <optional>
#include <string>
#include <thread>

#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif

#ifdef HAVE_GETOPT_LONG
#  include <getopt.h>
#elif defined(_WIN32)
#  include <third_party/win32/getopt.h>
#else
extern "C" {
#  include <third_party/getopt_long.h>
}
#endif

namespace core {

constexpr const char VERSION_TEXT[] =
  R"({0} version {1}
Features: {2}

Copyright (C) 2002-2007 Andrew Tridgell
Copyright (C) 2009-2022 Joel Rosdahl and other contributors

See <https://ccache.dev/credits.html> for a complete list of contributors.

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 3 of the License, or (at your option) any later
version.
)";

constexpr const char USAGE_TEXT[] =
  R"(Usage:
    {0} [options]
    {0} compiler [compiler options]
    compiler [compiler options]            (ccache masquerading as the compiler)

Common options:
    -c, --cleanup              delete old files and recalculate size counters
                               (normally not needed as this is done
                               automatically)
    -C, --clear                clear the cache completely (except configuration)
        --config-path PATH     operate on configuration file PATH instead of the
                               default
    -d, --dir PATH             operate on cache directory PATH instead of the
                               default
        --evict-namespace NAMESPACE
                               remove files created in namespace NAMESPACE
        --evict-older-than AGE remove files older than AGE (unsigned integer
                               with a d (days) or s (seconds) suffix)
    -F, --max-files NUM        set maximum number of files in cache to NUM (use
                               0 for no limit)
    -M, --max-size SIZE        set maximum size of cache to SIZE (use 0 for no
                               limit); available suffixes: k, M, G, T (decimal)
                               and Ki, Mi, Gi, Ti (binary); default suffix: G
    -X, --recompress LEVEL     recompress the cache to level LEVEL (integer or
                               "uncompressed")
        --recompress-threads THREADS
                               use up to THREADS threads when recompressing the
                               cache; default: number of CPUs
    -o, --set-config KEY=VAL   set configuration option KEY to value VAL
    -x, --show-compression     show compression statistics
    -p, --show-config          show current configuration options in
                               human-readable format
        --show-log-stats       print statistics counters from the stats log
                               in human-readable format
    -s, --show-stats           show summary of configuration and statistics
                               counters in human-readable format (use
                               -v/--verbose once or twice for more details)
    -v, --verbose              increase verbosity
    -z, --zero-stats           zero statistics counters

    -h, --help                 print this help text
    -V, --version              print version and copyright information

Options for remote file-based storage:
        --trim-dir PATH        remove old files from directory PATH until it is
                               at most the size specified by --trim-max-size
                               (note: don't use this option to trim the local
                               cache)
        --trim-max-size SIZE   specify the maximum size for --trim-dir;
                               available suffixes: k, M, G, T (decimal) and Ki,
                               Mi, Gi, Ti (binary); default suffix: G
        --trim-method METHOD   specify the method (atime or mtime) for
                               --trim-dir; default: atime
        --trim-recompress LEVEL
                               recompress to level LEVEL (integer or
                               "uncompressed")
        --trim-recompress-threads THREADS
                               use up to THREADS threads when recompressing;
                               default: number of CPUs

Options for scripting or debugging:
        --checksum-file PATH   print the checksum (128 bit XXH3) of the file at
                               PATH
        --extract-result PATH  extract file data stored in result file at PATH
                               to the current working directory
    -k, --get-config KEY       print the value of configuration key KEY
        --hash-file PATH       print the hash (160 bit BLAKE3) of the file at
                               PATH
        --inspect PATH         print result/manifest file at PATH in
                               human-readable format
        --print-stats          print statistics counter IDs and corresponding
                               values in machine-parsable format

See also the manual on <https://ccache.dev/documentation.html>.
)";

static void
configuration_printer(const std::string& key,
                      const std::string& value,
                      const std::string& origin)
{
  PRINT(stdout, "({}) {} = {}\n", origin, key, value);
}

static nonstd::expected<std::vector<uint8_t>, std::string>
read_from_path_or_stdin(const std::string& path)
{
  if (path == "-") {
    std::vector<uint8_t> output;
    const auto result =
      util::read_fd(STDIN_FILENO, [&](const uint8_t* data, size_t size) {
        output.insert(output.end(), data, data + size);
      });
    if (!result) {
      return nonstd::make_unexpected(
        FMT("Failed to read from stdin: {}", result.error()));
    }
    return output;
  } else {
    const auto result = util::read_file<std::vector<uint8_t>>(path);
    if (!result) {
      return nonstd::make_unexpected(
        FMT("Failed to read {}: {}", path, result.error()));
    }
    return *result;
  }
}

static int
inspect_path(const std::string& path)
{
  const auto cache_entry_data = read_from_path_or_stdin(path);
  if (!cache_entry_data) {
    PRINT(stderr, "Error: {}\n", cache_entry_data.error());
    return EXIT_FAILURE;
  }

  core::CacheEntry cache_entry(*cache_entry_data);
  fputs(cache_entry.header().inspect().c_str(), stdout);

  const auto payload = cache_entry.payload();

  switch (cache_entry.header().entry_type) {
  case core::CacheEntryType::manifest: {
    core::Manifest manifest;
    manifest.read(payload);
    manifest.inspect(stdout);
    break;
  }
  case core::CacheEntryType::result:
    Result::Deserializer result_deserializer(payload);
    ResultInspector result_inspector(stdout);
    result_deserializer.visit(result_inspector);
    break;
  }

  cache_entry.verify_checksum();

  return EXIT_SUCCESS;
}

static void
print_compression_statistics(const storage::local::CompressionStatistics& cs)
{
  const double ratio = cs.compr_size > 0
                         ? static_cast<double>(cs.content_size) / cs.compr_size
                         : 0.0;
  const double savings = ratio > 0.0 ? 100.0 - (100.0 / ratio) : 0.0;

  using C = util::TextTable::Cell;
  auto human_readable = Util::format_human_readable_size;
  util::TextTable table;

  table.add_row({
    "Total data:",
    C(human_readable(cs.compr_size + cs.incompr_size)).right_align(),
    FMT("({} disk blocks)", human_readable(cs.on_disk_size)),
  });
  table.add_row({
    "Compressed data:",
    C(human_readable(cs.compr_size)).right_align(),
    FMT("({:.1f}% of original size)", 100.0 - savings),
  });
  table.add_row({
    "  Original size:",
    C(human_readable(cs.content_size)).right_align(),
  });
  table.add_row({
    "  Compression ratio:",
    C(FMT("{:.3f} x ", ratio)).right_align(),
    FMT("({:.1f}% space savings)", savings),
  });
  table.add_row({
    "Incompressible data:",
    C(human_readable(cs.incompr_size)).right_align(),
  });

  PRINT_RAW(stdout, table.render());
}

static void
trim_dir(const std::string& dir,
         const uint64_t trim_max_size,
         const bool trim_lru_mtime,
         std::optional<std::optional<int8_t>> recompress_level,
         uint32_t recompress_threads)
{
  std::vector<Stat> files;
  uint64_t initial_size = 0;

  Util::traverse(dir, [&](const std::string& path, const bool is_dir) {
    if (is_dir || TemporaryFile::is_tmp_file(path)) {
      return;
    }
    auto stat = Stat::lstat(path);
    if (!stat) {
      // Probably some race, ignore.
      return;
    }
    initial_size += stat.size_on_disk();
    const auto name = Util::base_name(path);
    if (name == "ccache.conf" || name == "stats") {
      throw Fatal(
        FMT("this looks like a local cache directory (found {})", path));
    }
    files.emplace_back(std::move(stat));
  });

  std::sort(files.begin(), files.end(), [&](const auto& f1, const auto& f2) {
    return trim_lru_mtime ? f1.mtime() < f2.mtime() : f1.atime() < f2.atime();
  });

  int64_t recompression_diff = 0;

  if (recompress_level) {
    const size_t read_ahead = std::max(
      static_cast<size_t>(10), 2 * static_cast<size_t>(recompress_threads));
    ThreadPool thread_pool(recompress_threads, read_ahead);
    core::FileRecompressor recompressor;

    std::atomic<uint64_t> incompressible_size = 0;
    for (auto& file : files) {
      thread_pool.enqueue([&] {
        try {
          auto new_stat = recompressor.recompress(
            file, *recompress_level, core::FileRecompressor::KeepAtime::yes);
          file = std::move(new_stat); // Remember new size, if any.
        } catch (core::Error&) {
          // Ignore for now.
          incompressible_size += file.size_on_disk();
        }
      });
    }

    thread_pool.shut_down();
    recompression_diff = recompressor.new_size() - recompressor.old_size();
    PRINT(stdout,
          "Recompressed {} to {} ({})\n",
          Util::format_human_readable_size(incompressible_size
                                           + recompressor.old_size()),
          Util::format_human_readable_size(incompressible_size
                                           + recompressor.new_size()),
          Util::format_human_readable_diff(recompression_diff));
  }

  uint64_t size_after_recompression = initial_size + recompression_diff;
  uint64_t final_size = size_after_recompression;

  size_t removed_files = 0;
  for (const auto& file : files) {
    if (final_size <= trim_max_size) {
      break;
    }
    if (Util::unlink_tmp(file.path())) {
      ++removed_files;
      final_size -= file.size_on_disk();
    }
  }

  PRINT(stdout,
        "Trimmed {} to {} ({}, {}{} file{})\n",
        Util::format_human_readable_size(size_after_recompression),
        Util::format_human_readable_size(final_size),
        Util::format_human_readable_diff(final_size - size_after_recompression),
        removed_files == 0 ? "" : "-",
        removed_files,
        removed_files == 1 ? "" : "s");
}

std::optional<int8_t>
parse_compression_level(std::string_view level)
{
  if (level == "uncompressed") {
    return std::nullopt;
  } else {
    return util::value_or_throw<Error>(
      util::parse_signed(level, INT8_MIN, INT8_MAX, "compression level"));
  }
}

static std::string
get_version_text(const std::string_view ccache_name)
{
  return FMT(
    VERSION_TEXT, ccache_name, CCACHE_VERSION, storage::get_features());
}

std::string
get_usage_text(const std::string_view ccache_name)
{
  return FMT(USAGE_TEXT, ccache_name);
}

enum {
  CHECKSUM_FILE,
  CONFIG_PATH,
  DUMP_MANIFEST,
  DUMP_RESULT,
  EVICT_NAMESPACE,
  EVICT_OLDER_THAN,
  EXTRACT_RESULT,
  HASH_FILE,
  INSPECT,
  PRINT_STATS,
  RECOMPRESS_THREADS,
  SHOW_LOG_STATS,
  TRIM_DIR,
  TRIM_MAX_SIZE,
  TRIM_METHOD,
  TRIM_RECOMPRESS,
  TRIM_RECOMPRESS_THREADS,
};

const char options_string[] = "cCd:k:hF:M:po:svVxX:z";
const option long_options[] = {
  {"checksum-file", required_argument, nullptr, CHECKSUM_FILE},
  {"cleanup", no_argument, nullptr, 'c'},
  {"clear", no_argument, nullptr, 'C'},
  {"config-path", required_argument, nullptr, CONFIG_PATH},
  {"dir", required_argument, nullptr, 'd'},
  {"directory", required_argument, nullptr, 'd'},               // bwd compat
  {"dump-manifest", required_argument, nullptr, DUMP_MANIFEST}, // bwd compat
  {"dump-result", required_argument, nullptr, DUMP_RESULT},     // bwd compat
  {"evict-namespace", required_argument, nullptr, EVICT_NAMESPACE},
  {"evict-older-than", required_argument, nullptr, EVICT_OLDER_THAN},
  {"extract-result", required_argument, nullptr, EXTRACT_RESULT},
  {"get-config", required_argument, nullptr, 'k'},
  {"hash-file", required_argument, nullptr, HASH_FILE},
  {"help", no_argument, nullptr, 'h'},
  {"inspect", required_argument, nullptr, INSPECT},
  {"max-files", required_argument, nullptr, 'F'},
  {"max-size", required_argument, nullptr, 'M'},
  {"print-stats", no_argument, nullptr, PRINT_STATS},
  {"recompress", required_argument, nullptr, 'X'},
  {"recompress-threads", required_argument, nullptr, RECOMPRESS_THREADS},
  {"set-config", required_argument, nullptr, 'o'},
  {"show-compression", no_argument, nullptr, 'x'},
  {"show-config", no_argument, nullptr, 'p'},
  {"show-log-stats", no_argument, nullptr, SHOW_LOG_STATS},
  {"show-stats", no_argument, nullptr, 's'},
  {"trim-dir", required_argument, nullptr, TRIM_DIR},
  {"trim-max-size", required_argument, nullptr, TRIM_MAX_SIZE},
  {"trim-method", required_argument, nullptr, TRIM_METHOD},
  {"trim-recompress", required_argument, nullptr, TRIM_RECOMPRESS},
  {"trim-recompress-threads",
   required_argument,
   nullptr,
   TRIM_RECOMPRESS_THREADS},
  {"verbose", no_argument, nullptr, 'v'},
  {"version", no_argument, nullptr, 'V'},
  {"zero-stats", no_argument, nullptr, 'z'},
  {nullptr, 0, nullptr, 0}};

int
process_main_options(int argc, const char* const* argv)
{
  int c;

  uint8_t verbosity = 0;

  std::optional<uint64_t> trim_max_size;
  bool trim_lru_mtime = false;
  std::optional<std::optional<int8_t>> trim_recompress;
  uint32_t trim_recompress_threads = std::thread::hardware_concurrency();

  std::optional<std::string> evict_namespace;
  std::optional<uint64_t> evict_max_age;

  uint32_t recompress_threads = std::thread::hardware_concurrency();

  // First pass: Handle non-command options that affect command options.
  while ((c = getopt_long(argc,
                          const_cast<char* const*>(argv),
                          options_string,
                          long_options,
                          nullptr))
         != -1) {
    const std::string arg = optarg ? optarg : std::string();

    switch (c) {
    case 'd': // --dir
      Util::setenv("CCACHE_DIR", arg);
      break;

    case CONFIG_PATH:
      Util::setenv("CCACHE_CONFIGPATH", arg);
      break;

    case RECOMPRESS_THREADS:
      recompress_threads = util::value_or_throw<Error>(util::parse_unsigned(
        arg, 1, std::numeric_limits<uint32_t>::max(), "threads"));
      break;

    case TRIM_MAX_SIZE:
      trim_max_size = Util::parse_size(arg);
      break;

    case TRIM_METHOD:
      trim_lru_mtime = (arg == "ctime");
      break;

    case TRIM_RECOMPRESS:
      trim_recompress = parse_compression_level(arg);
      break;

    case TRIM_RECOMPRESS_THREADS:
      trim_recompress_threads =
        util::value_or_throw<Error>(util::parse_unsigned(
          arg, 1, std::numeric_limits<uint32_t>::max(), "threads"));
      break;

    case 'v': // --verbose
      ++verbosity;
      break;

    case '?': // unknown option
      return EXIT_FAILURE;
    }
  }

  // Second pass: Handle command options in order.
  optind = 1;
  while ((c = getopt_long(argc,
                          const_cast<char* const*>(argv),
                          options_string,
                          long_options,
                          nullptr))
         != -1) {
    Config config;
    config.read();

    UmaskScope umask_scope(config.umask());

    const std::string arg = optarg ? optarg : std::string();

    switch (c) {
    case CONFIG_PATH:
    case 'd': // --dir
    case RECOMPRESS_THREADS:
    case TRIM_MAX_SIZE:
    case TRIM_METHOD:
    case TRIM_RECOMPRESS:
    case TRIM_RECOMPRESS_THREADS:
    case 'v': // --verbose
      // Already handled in the first pass.
      break;

    case CHECKSUM_FILE: {
      util::XXH3_128 checksum;
      Fd fd(arg == "-" ? STDIN_FILENO : open(arg.c_str(), O_RDONLY));
      if (fd) {
        util::read_fd(*fd, [&checksum](const uint8_t* data, size_t size) {
          checksum.update({data, size});
        });
        const auto digest = checksum.digest();
        PRINT(
          stdout, "{}\n", Util::format_base16(digest.data(), digest.size()));
      } else {
        PRINT(stderr, "Error: Failed to checksum {}\n", arg);
      }
      break;
    }

    case EVICT_NAMESPACE: {
      evict_namespace = arg;
      break;
    }

    case EVICT_OLDER_THAN: {
      evict_max_age = Util::parse_duration(arg);
      break;
    }

    case EXTRACT_RESULT: {
      umask_scope.release(); // Use original umask for files outside cache dir
      const auto cache_entry_data = read_from_path_or_stdin(arg);
      if (!cache_entry_data) {
        PRINT(stderr, "Error: \"{}\"", cache_entry_data.error());
        return EXIT_FAILURE;
      }
      std::optional<ResultExtractor::GetRawFilePathFunction> get_raw_file_path;
      if (arg != "-") {
        get_raw_file_path = [&](uint8_t file_number) {
          return storage::local::LocalStorage::get_raw_file_path(arg,
                                                                 file_number);
        };
      }
      ResultExtractor result_extractor(".", get_raw_file_path);
      core::CacheEntry cache_entry(*cache_entry_data);
      const auto payload = cache_entry.payload();

      Result::Deserializer result_deserializer(payload);
      result_deserializer.visit(result_extractor);
      cache_entry.verify_checksum();
      return EXIT_SUCCESS;
    }

    case HASH_FILE: {
      Hash hash;
      const auto result =
        arg == "-" ? hash.hash_fd(STDIN_FILENO) : hash.hash_file(arg);
      if (result) {
        PRINT(stdout, "{}\n", hash.digest().to_string());
      } else {
        PRINT(stderr, "Error: Failed to hash {}: {}\n", arg, result.error());
        return EXIT_FAILURE;
      }
      break;
    }

    case INSPECT:
    case DUMP_MANIFEST: // Backward compatibility
    case DUMP_RESULT:   // Backward compatibility
      return inspect_path(arg);

    case PRINT_STATS: {
      const auto [counters, last_updated] =
        storage::local::LocalStorage(config).get_all_statistics();
      Statistics statistics(counters);
      PRINT_RAW(stdout, statistics.format_machine_readable(last_updated));
      break;
    }

    case 'c': // --cleanup
    {
      ProgressBar progress_bar("Cleaning...");
      storage::local::LocalStorage(config).clean_all(
        [&](double progress) { progress_bar.update(progress); });
      if (isatty(STDOUT_FILENO)) {
        PRINT_RAW(stdout, "\n");
      }
      break;
    }

    case 'C': // --clear
    {
      ProgressBar progress_bar("Clearing...");
      storage::local::LocalStorage(config).wipe_all(
        [&](double progress) { progress_bar.update(progress); });
      if (isatty(STDOUT_FILENO)) {
        PRINT_RAW(stdout, "\n");
      }
      break;
    }

    case 'h': // --help
      PRINT(stdout, USAGE_TEXT, Util::base_name(argv[0]));
      return EXIT_SUCCESS;

    case 'k': // --get-config
      PRINT(stdout, "{}\n", config.get_string_value(arg));
      break;

    case 'F': { // --max-files
      auto files = util::value_or_throw<Error>(util::parse_unsigned(arg));
      config.set_value_in_file(config.config_path(), "max_files", arg);
      if (files == 0) {
        PRINT_RAW(stdout, "Unset cache file limit\n");
      } else {
        PRINT(stdout, "Set cache file limit to {}\n", files);
      }
      break;
    }

    case 'M': { // --max-size
      uint64_t size = Util::parse_size(arg);
      config.set_value_in_file(config.config_path(), "max_size", arg);
      if (size == 0) {
        PRINT_RAW(stdout, "Unset cache size limit\n");
      } else {
        PRINT(stdout,
              "Set cache size limit to {}\n",
              Util::format_human_readable_size(size));
      }
      break;
    }

    case 'o': { // --set-config
      // Start searching for equal sign at position 1 to improve error message
      // for the -o=K=V case (key "=K" and value "V").
      size_t eq_pos = arg.find('=', 1);
      if (eq_pos == std::string::npos) {
        throw Error(FMT("missing equal sign in \"{}\"", arg));
      }
      std::string key = arg.substr(0, eq_pos);
      std::string value = arg.substr(eq_pos + 1);
      config.set_value_in_file(config.config_path(), key, value);
      break;
    }

    case 'p': // --show-config
      config.visit_items(configuration_printer);
      break;

    case SHOW_LOG_STATS: {
      if (config.stats_log().empty()) {
        throw Fatal("No stats log has been configured");
      }
      Statistics statistics(StatsLog(config.stats_log()).read());
      const auto timestamp =
        Stat::stat(config.stats_log(), Stat::OnError::log).mtime();
      PRINT_RAW(
        stdout,
        statistics.format_human_readable(config, timestamp, verbosity, true));
      break;
    }

    case 's': { // --show-stats
      const auto [counters, last_updated] =
        storage::local::LocalStorage(config).get_all_statistics();
      Statistics statistics(counters);
      PRINT_RAW(stdout,
                statistics.format_human_readable(
                  config, last_updated, verbosity, false));
      break;
    }

    case TRIM_DIR:
      if (!trim_max_size) {
        throw Error("please specify --trim-max-size when using --trim-dir");
      }
      trim_dir(arg,
               *trim_max_size,
               trim_lru_mtime,
               trim_recompress,
               trim_recompress_threads);
      break;

    case 'V': // --version
    {
      std::string_view name = Util::base_name(argv[0]);
#ifdef _WIN32
      name = Util::remove_extension(name);
#endif
      PRINT_RAW(stdout, get_version_text(name));
      break;
    }

    case 'x': // --show-compression
    {
      ProgressBar progress_bar("Scanning...");
      const auto compression_statistics =
        storage::local::LocalStorage(config).get_compression_statistics(
          [&](double progress) { progress_bar.update(progress); });
      if (isatty(STDOUT_FILENO)) {
        PRINT_RAW(stdout, "\n\n");
      }
      print_compression_statistics(compression_statistics);
      break;
    }

    case 'X': // --recompress
    {
      auto wanted_level = parse_compression_level(arg);

      ProgressBar progress_bar("Recompressing...");
      storage::local::LocalStorage(config).recompress(
        wanted_level, recompress_threads, [&](double progress) {
          progress_bar.update(progress);
        });
      break;
    }

    case 'z': // --zero-stats
      storage::local::LocalStorage(config).zero_all_statistics();
      PRINT_RAW(stdout, "Statistics zeroed\n");
      break;

    default:
      PRINT(stderr, USAGE_TEXT, Util::base_name(argv[0]));
      return EXIT_FAILURE;
    }
  }

  if (evict_max_age || evict_namespace) {
    Config config;
    config.read();

    ProgressBar progress_bar("Evicting...");
    storage::local::LocalStorage(config).evict(
      [&](double progress) { progress_bar.update(progress); },
      evict_max_age,
      evict_namespace);
    if (isatty(STDOUT_FILENO)) {
      PRINT_RAW(stdout, "\n");
    }
  }

  return EXIT_SUCCESS;
}

} // namespace core
