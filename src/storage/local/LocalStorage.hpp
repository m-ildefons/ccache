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

#pragma once

#include <Digest.hpp>
#include <core/Result.hpp>
#include <core/StatisticsCounters.hpp>
#include <core/types.hpp>
#include <storage/local/util.hpp>
#include <storage/types.hpp>
#include <util/Bytes.hpp>
#include <util/TimePoint.hpp>

#include <third_party/nonstd/span.hpp>

#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

class Config;

namespace storage {
namespace local {

struct CompressionStatistics
{
  uint64_t compr_size;
  uint64_t content_size;
  uint64_t incompr_size;
  uint64_t on_disk_size;
};

enum class FileType { result, manifest, raw, unknown };

FileType file_type_from_path(std::string_view path);

class LocalStorage
{
public:
  LocalStorage(const Config& config);

  void finalize();

  // --- Cache entry handling ---

  std::optional<util::Bytes> get(const Digest& key, core::CacheEntryType type);

  void put(const Digest& key,
           core::CacheEntryType type,
           nonstd::span<const uint8_t> value,
           bool only_if_missing = false);

  void remove(const Digest& key, core::CacheEntryType type);

  static std::string get_raw_file_path(std::string_view result_path,
                                       uint8_t file_number);
  std::string get_raw_file_path(const Digest& result_key,
                                uint8_t file_number) const;

  void
  put_raw_files(const Digest& key,
                const std::vector<core::Result::Serializer::RawFile> raw_files);

  // --- Statistics ---

  void increment_statistic(core::Statistic statistic, int64_t value = 1);
  void increment_statistics(const core::StatisticsCounters& statistics);

  const core::StatisticsCounters& get_statistics_updates() const;

  // Zero all statistics counters except those tracking cache size and number of
  // files in the cache.
  void zero_all_statistics();

  // Get statistics and last time of update for the whole local storage cache.
  std::pair<core::StatisticsCounters, util::TimePoint>
  get_all_statistics() const;

  // --- Cleanup ---

  void evict(const ProgressReceiver& progress_receiver,
             std::optional<uint64_t> max_age,
             std::optional<std::string> namespace_);

  void clean_all(const ProgressReceiver& progress_receiver);

  void wipe_all(const ProgressReceiver& progress_receiver);

  // --- Compression ---

  CompressionStatistics
  get_compression_statistics(const ProgressReceiver& progress_receiver) const;

  void recompress(std::optional<int8_t> level,
                  uint32_t threads,
                  const ProgressReceiver& progress_receiver);

private:
  const Config& m_config;

  // Main statistics updates (result statistics and size/count change for result
  // file) which get written into the statistics file belonging to the result
  // file.
  core::StatisticsCounters m_result_counter_updates;

  // Statistics updates (only for manifest size/count change) which get written
  // into the statistics file belonging to the manifest.
  core::StatisticsCounters m_manifest_counter_updates;

  // The manifest and result keys and paths are stored by put() so that
  // finalize() can use them to move the files in place.
  std::optional<Digest> m_manifest_key;
  std::optional<Digest> m_result_key;
  std::string m_manifest_path;
  std::string m_result_path;

  std::vector<std::string> m_added_raw_files;

  struct LookUpCacheFileResult
  {
    std::string path;
    Stat stat;
    uint8_t level;
  };

  LookUpCacheFileResult look_up_cache_file(const Digest& key,
                                           core::CacheEntryType type) const;

  void clean_internal_tempdir();

  std::optional<core::StatisticsCounters>
  update_stats_and_maybe_move_cache_file(
    const Digest& key,
    const std::string& current_path,
    const core::StatisticsCounters& counter_updates,
    core::CacheEntryType type);

  // Join the cache directory, a '/' and `name` into a single path and return
  // it. Additionally, `level` single-character, '/'-separated subpaths are
  // split from the beginning of `name` before joining them all.
  std::string get_path_in_cache(uint8_t level, std::string_view name) const;

  static void clean_dir(const std::string& subdir,
                        uint64_t max_size,
                        uint64_t max_files,
                        std::optional<uint64_t> max_age,
                        std::optional<std::string> namespace_,
                        const ProgressReceiver& progress_receiver);
};

// --- Inline implementations ---

inline const core::StatisticsCounters&
LocalStorage::get_statistics_updates() const
{
  return m_result_counter_updates;
}

} // namespace local
} // namespace storage
