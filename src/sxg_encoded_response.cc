// Copyright 2019 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

#include <cstring>
#include <openssl/sha.h>
#include "libsxg/sxg_raw_response.hpp"
#include "libsxg/sxg_encoded_response.hpp"

#include "libsxg/internal/sxg_codec.h"

namespace sxg {

static const char* kIntegrityPrefix = "sha256-";

EncodedResponse EncodedResponse::Encode(const size_t mi_record_size,
                                        const RawResponse& src) {
  std::string digest_value;
  digest_value.resize(sxg_base64encode_size(SHA256_DIGEST_LENGTH));

  uint8_t digest[SHA256_DIGEST_LENGTH];
  EncodedResponse result;
  result.header_ = src.header;
  result.header_.Append("content-encoding", "mi-sha-256-03");
  result.header_.Append(":status", "200");
  result.header_.Append("digest", "mi-sha256-03=");

  size_t encoded_size =
    sxg_mi_sha256_size(src.payload.size(), mi_record_size);
  uint8_t proof[SHA256_DIGEST_LENGTH];
  result.payload_.resize(encoded_size);
  sxg_encode_mi_sha256(reinterpret_cast<const uint8_t*>(src.payload.data()),
                       src.payload.length(), mi_record_size,
                       reinterpret_cast<uint8_t*>(&result.payload_[0]), proof);
  result.header_.Append("content-encoding", "mi-sha256-03");

  sxg_base64encode(digest, SHA256_DIGEST_LENGTH,
                   reinterpret_cast<uint8_t*>(&digest_value[0]));
  result.header_.Append("digest", "mi-sha256-03=" + digest_value);

  return result;
}


std::string EncodedResponse::GetHeaderIntegrity() const {
  std::string result;
  result.resize(strlen(kIntegrityPrefix) + sxg_base64encode_size(SHA256_DIGEST_LENGTH));
  uint8_t* pos = reinterpret_cast<uint8_t *>(&result[0]);
  memcpy(pos, kIntegrityPrefix, strlen(kIntegrityPrefix));
  pos += strlen(kIntegrityPrefix);

  std::string header_cbor = header_.SerializeInCbor();
  uint8_t digest[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const uint8_t *>(header_cbor.data()), header_cbor.size(), digest);
  sxg_base64encode(digest, SHA256_DIGEST_LENGTH, pos);

  return result;
}

}  // namespace sxg
