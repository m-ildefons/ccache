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

#include "S3Storage.hpp"

#include <Digest.hpp>
#include <Logging.hpp>
#include <ccache.hpp>
#include <core/exceptions.hpp>
#include <fmtmacros.hpp>
#include <util/Bytes.hpp>
#include <util/expected.hpp>
#include <util/string.hpp>
#include <util/types.hpp>

// #include <third_party/httplib.h>
// #include <third_party/url.hpp>

#include <aws/core/Aws.h>
#include <aws/core/auth/AWSCredentialsProvider.h>
#include <aws/core/http/Scheme.h>
#include <aws/core/utils/StringUtils.h>
#include <aws/core/utils/UUID.h>
#include <aws/core/utils/memory/AWSMemory.h>
#include <aws/s3/S3Client.h>
#include <aws/s3/model/BucketLocationConstraint.h>
#include <aws/s3/model/CreateBucketRequest.h>
#include <aws/s3/model/DeleteObjectRequest.h>
#include <aws/s3/model/GetObjectRequest.h>
#include <aws/s3/model/PutObjectRequest.h>

#include <string_view>
#include <cstdint>


namespace storage::remote {

namespace {

const bool        k_default_use_tls     = true;
const std::string k_default_aws_region  = "us-east-1";
const std::string k_default_bucket      = "ccache";
const std::string k_default_access_key  = "ccache";
const std::string k_default_secret_key  = "ccache";


class S3StorageBackend : public RemoteStorage::Backend
{
public:
  S3StorageBackend(const Params& params);
  ~S3StorageBackend() override;

  nonstd::expected<std::optional<util::Bytes>, Failure>
  get(const Digest& key) override;

  nonstd::expected<bool, Failure>
  put(const Digest& key,
      nonstd::span<const uint8_t> value,
      bool only_if_missing) override;

  nonstd::expected<bool, Failure>
  remove(const Digest& key) override;

private:
  bool         m_use_tls;
  std::string  m_access_key;
  std::string  m_region;
  std::string  m_bucket_name;
  std::string  m_endpoint_url;
  std::string  m_secret_key;

  Aws::SDKOptions                                   m_aws_options;
  Aws::UniquePtr<Aws::Client::ClientConfiguration>  m_aws_client_config;
  Aws::UniquePtr<Aws::S3::S3Client>                 m_aws_s3;
};  // class S3StorageBackend


// --- Helper Functions
//const char base[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwcyz0123456789-_";
const char base[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwcyz0123456789+/";
const char pad = '=';


std::string
base64 (const util::Bytes bytes) {
  std::string chars;

  for (size_t i = 0; i < bytes.size(); i += 3) {
    if (i + 2 < bytes.size()) {
      chars += base[(bytes[i] & 0xfc) >> 2];
      chars += base[(bytes[i] & 0x03) << 4 | (bytes[i+1] & 0xf0) >> 4];
      chars += base[(bytes[i+1] & 0x0f) << 2 | (bytes[i+2] & 0xc0) >> 6];
      chars += base[(bytes[i+2] & 0x3f)];
    } else if (i + 1 < bytes.size()) {
      chars += base[(bytes[i] & 0xfc ) >> 2];
      chars += base[(bytes[i] & 0x03 ) << 4 | ( bytes[i+1] & 0xf0) >> 4];
      chars += base[(bytes[i+1] & 0x0f ) << 2];
      chars += pad;
    } else {
      chars += base[(bytes[i] & 0xfc) >> 2];
      chars += base[(bytes[i] & 0x03) << 4];
      chars += pad;
      chars += pad;
    }
  }

  return chars;
}


int base_idx(const char chr) {
  if (base[0] <= chr && chr <= base[25]) {
    return chr - 65;
  } else if (base[26] <= chr && chr <= base[51]) {
    return chr - 71;
  } else if (base[52] <= chr && chr <= base[61]) {
    return chr + 4;
  } else if (chr == base[62]) {
    return 62;
  } else if (chr == base[63]) {
    return 63;
  } else {
    return 64;
  }
}

util::Bytes
unbase64 (const std::string chars) {
  util::Bytes bytes(chars.size() / 4 * 3);

  for (size_t i = 0; i < chars.size(); i+= 4) {
    if (chars[i+2] == pad && chars[i+3] == pad) {
      bytes[i / 4 * 3] = (base_idx(chars[i]) << 2 | (base_idx(chars[i+1]) & 0x30) >> 4);
    } else if (chars[i+3] == pad) {
      bytes[i / 4 * 3] = (base_idx(chars[i]) << 2 | (base_idx(chars[i+1]) & 0x30) >> 4);
      bytes[i / 4 * 3] = ((base_idx(chars[i+1]) & 0x0f) << 4 | (base_idx(chars[i+2]) & 0x3d) >> 2);
    } else {
      bytes[i / 4 * 3] = (base_idx(chars[i]) << 2 | (base_idx(chars[i+1]) & 0x30) >> 4);
      bytes[i / 4 * 3] = ((base_idx(chars[i+1]) & 0x0f) << 4 | (base_idx(chars[i+2]) & 0x3d) >> 2);
      bytes[i / 4 * 3] = ((base_idx(chars[i+2]) & 0x03) << 6 | base_idx(chars[i+3]));
    }
  }

  return bytes;
}



std::string
get_url(const Url& url)
{
  // TODO: Convert S3://host:port/prefix into host:port/prefix here
  std::string url_str = url.str();
  return url_str.replace(url_str.begin(), url_str.begin() + 5, "");
}

// --- S3 Storage Backend Public Methods

S3StorageBackend::S3StorageBackend(const Params& params)
  : m_use_tls       (k_default_use_tls),
    m_access_key    (k_default_access_key),
    m_region        (k_default_aws_region),
    m_bucket_name   (k_default_bucket),
    m_endpoint_url  (get_url(params.url)),
    m_secret_key    (k_default_secret_key)
{
  for (const auto& attr : params.attributes) {
    if (attr.key == "region") {
      m_region = attr.value;
    } else if (attr.key == "bucket") {
      m_bucket_name = attr.value;
    } else if (attr.key == "access_key") {
      m_access_key = attr.value;
    } else if (attr.key == "secret_key") {
      m_secret_key = attr.value;
    } else if (attr.key == "use_tls") {
      m_use_tls = (attr.value == "true");
      if (m_use_tls) {
        m_endpoint_url.replace(m_endpoint_url.begin(),
                               m_endpoint_url.begin()+4,
                               "https");
      }
    } else {
      LOG("Unknown attribute: {}", attr.key);
    }
  }
  LOG("S3 Configuration:{}", "");
  LOG("  url: {}", m_endpoint_url);
  LOG("  region: {}", m_region);
  LOG("  bucket: {}", m_bucket_name);
  LOG("  access_key: {}", m_access_key);
  LOG("  secret_key: {}", m_secret_key);
  LOG("  use TLS: {}", m_use_tls ? "true" : "false");

  // Initialize S3 Client
  m_aws_options.loggingOptions.logLevel = Aws::Utils::Logging::LogLevel::Debug;
  Aws::InitAPI(m_aws_options);
  m_aws_client_config = Aws::MakeUnique<Aws::Client::ClientConfiguration>("configTag");
  m_aws_client_config->region            = m_region;
  m_aws_client_config->endpointOverride  = m_endpoint_url;
  m_aws_client_config->verifySSL         = m_use_tls;
  m_aws_client_config->scheme            = m_use_tls ? Aws::Http::Scheme::HTTPS
                                                     : Aws::Http::Scheme::HTTP;

  m_aws_s3 = Aws::MakeUnique<Aws::S3::S3Client>("clientTag",
                Aws::Auth::AWSCredentials(Aws::String(m_access_key),
                                          Aws::String(m_secret_key)),
                *m_aws_client_config);

  // Check if bucket exists
  auto bucket_list_outcome = m_aws_s3->ListBuckets();

  if (bucket_list_outcome.IsSuccess()) {
    auto bucket_found = false;
    auto buckets = bucket_list_outcome.GetResult().GetBuckets();

    if (!buckets.empty()) {
      for (auto&& bucket : buckets) {
        if (m_bucket_name == bucket.GetName()) {
          bucket_found = true;
          break;
        }
      }
    }

    if (!bucket_found) {
      Aws::S3::Model::CreateBucketConfiguration bucket_create_config;
      bucket_create_config.SetLocationConstraint(Aws::S3::Model::BucketLocationConstraint::NOT_SET);

      Aws::S3::Model::CreateBucketRequest bucket_create_request;
      bucket_create_request.SetBucket(m_bucket_name);
      bucket_create_request.SetCreateBucketConfiguration(bucket_create_config);

      auto bucket_create_outcome = m_aws_s3->CreateBucket(bucket_create_request);

      if (!bucket_create_outcome.IsSuccess()) {
        LOG("Failed to create Bucket with error: {}",
            bucket_create_outcome.GetError().GetMessage());
      } else {
        LOG("Bucket {} created.", m_bucket_name);
      }
    } else {
      LOG("Bucket {} found.", m_bucket_name);
    }
  } else {
    LOG("Failed to list buckets with error: {}",
        bucket_list_outcome.GetError().GetMessage());
  }
}

S3StorageBackend::~S3StorageBackend()
{
  Aws::ShutdownAPI(m_aws_options);
}

nonstd::expected<std::optional<util::Bytes>,
                 RemoteStorage::Backend::Failure>
S3StorageBackend::get(const Digest& key)
{
  Aws::S3::Model::GetObjectRequest get_object_request;
  get_object_request.SetBucket(m_bucket_name);
  get_object_request.SetKey((m_bucket_name + "/" + key.to_string()));

  auto get_object_outcome = m_aws_s3->GetObject(get_object_request);

  if (get_object_outcome.IsSuccess()) {
    auto&  data = get_object_outcome.GetResultWithOwnership().GetBody();

    std::string cached;
    data >> cached;

    return unbase64(cached);
  }

  LOG("Not found: {}", key.to_string());
  return std::nullopt;
}

nonstd::expected<bool, RemoteStorage::Backend::Failure>
S3StorageBackend::put(const Digest& key,
                      nonstd::span<const uint8_t> value,
                      bool only_if_missing)
{
  // TODO: implement only_if_missing logic
  const std::shared_ptr<Aws::IOStream> body =
    Aws::MakeShared<Aws::StringStream>("");

  std::string data = base64(value);
  *body << data;

  Aws::S3::Model::PutObjectRequest put_object_request;
  put_object_request.SetBucket(m_bucket_name);
  put_object_request.SetKey((m_bucket_name + "/" + key.to_string()));
  put_object_request.SetBody(body);

  auto put_object_outcome = m_aws_s3->PutObject(put_object_request);

  if (put_object_outcome.IsSuccess()) {
    return true;
  }

  LOG("Failed to cache {}", key.to_string());
  LOG("  with length {}", data.size());
  LOG("  ({})", only_if_missing);
  LOG("  Error: {}", put_object_outcome.GetError().GetMessage());
  return nonstd::make_unexpected(Failure::error);
}

nonstd::expected<bool, RemoteStorage::Backend::Failure>
S3StorageBackend::remove(const Digest& key)
{
  Aws::S3::Model::DeleteObjectRequest delete_object_request;
  delete_object_request.SetBucket(m_bucket_name);
  delete_object_request.SetKey((m_bucket_name + "/" + key.to_string()));

  auto delete_object_outcome = m_aws_s3->DeleteObject(delete_object_request);

  if (delete_object_outcome.IsSuccess()) {
    return true;
  }

  LOG("Failed to remove {}", key.to_string());
  LOG("Not yet implemented: {}", "remove");
  return nonstd::make_unexpected(Failure::error);
}

} // namespace

// --- S3 Storage Public Methods

std::unique_ptr<RemoteStorage::Backend>
S3Storage::create_backend(const Backend::Params& params) const
{
  LOG("Using {} Storage Backend", "S3");
  return std::make_unique<S3StorageBackend>(params);
}

void
S3Storage::redact_secrets(Backend::Params& params) const
{
  auto& url = params.url;
  url.user_info("");
}

}  // namespace storage::remote
