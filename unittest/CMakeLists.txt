set(
  source_files
  TestUtil.cpp
  main.cpp
  test_Args.cpp
  test_AtomicFile.cpp
  test_Config.cpp
  test_Depfile.cpp
  test_Hash.cpp
  test_Stat.cpp
  test_Util.cpp
  test_argprocessing.cpp
  test_ccache.cpp
  test_compopt.cpp
  test_compression_types.cpp
  test_core_MsvcShowIncludesOutput.cpp
  test_core_Statistics.cpp
  test_core_StatisticsCounters.cpp
  test_core_StatsLog.cpp
  test_hashutil.cpp
  test_storage_local_StatsFile.cpp
  test_storage_local_util.cpp
  test_util_Bytes.cpp
  test_util_Duration.cpp
  test_util_LockFile.cpp
  test_util_TextTable.cpp
  test_util_TimePoint.cpp
  test_util_Tokenizer.cpp
  test_util_XXH3_128.cpp
  test_util_XXH3_64.cpp
  test_util_expected.cpp
  test_util_file.cpp
  test_util_path.cpp
  test_util_string.cpp
  test_util_zstd.cpp
)

if(INODE_CACHE_SUPPORTED)
  list(APPEND source_files test_InodeCache.cpp)
endif()

if(WIN32)
  list(APPEND source_files test_bsdmkstemp.cpp test_Win32Util.cpp)
endif()

file(GLOB headers *.hpp)
list(APPEND source_files ${headers})

add_executable(unittest ${source_files})

if(MSVC)
  # Turn off /Zc:preprocessor for this test because it triggers a bug in some older Windows 10 SDK headers.
  set_source_files_properties(test_Stat.cpp PROPERTIES COMPILE_FLAGS /Zc:preprocessor-)
endif()

target_link_libraries(
  unittest
  PRIVATE standard_settings standard_warnings ccache_framework third_party)

target_include_directories(unittest PRIVATE ${CMAKE_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR} ${ccache_SOURCE_DIR}/src)

add_test(NAME unittest COMMAND unittest)
