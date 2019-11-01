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

#include "libsxg/sxg_raw_response.hpp"
#include "libsxg/sxg_encoded_response.hpp"

#include "libsxg/internal/sxg_codec.h"
#include "libsxg/internal/sxg_header.h"

namespace sxg {

EncodedResponse EncodedResponse::Encode(const size_t mi_record_size,
                                        const RawResponse& src) {
  sxg_buffer_t digest_value = sxg_empty_buffer();
  uint8_t digest[SHA256_DIGEST_LENGTH];
  EncodedResponse result;
  result.header_ = src.header;
  result.header_.Append("content-encoding", "mi-sha-256-03");
  result.header_.Append(":status", "200");
  result.header_.Append("digest", "mi-sha256-03=");

  sxg_encode_mi_sha256(&src->payload, mi_record_size, &dst->payload,
                       digest);
  result.Append("content-encoding", "mi-sha256-03");
  sxg_write_string("mi-sha256-03=", &digest_value) &&
      sxg_base64encode_bytes(digest, SHA256_DIGEST_LENGTH, &digest_value) &&
      sxg_header_append_buffer("digest", &digest_value, &dst->header);

  sxg_buffer_release(&digest_value);
  if (!success) {
    sxg_encoded_response_release(dst);
  }
  return success;
}

std::string EncodedResponse::GetHeaderIntegrity() const {
  std::string result = header_.SerializeInCbor();
  const bool success = sxg_header_serialize_cbor(&src->header, &cbor) &&
                       sxg_calc_sha256(&cbor, &hashed) &&
                       sxg_write_string("sha256-", dst) &&
                       sxg_base64encode(&hashed, dst);
  return success;
}

void sxg_encoded_response_release(sxg_encoded_response_t* target) {
  sxg_header_release(&target->header);
  sxg_buffer_release(&target->payload);
}

}  // namespace sxg
