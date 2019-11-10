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

#ifndef LIBSXG_SXG_ENCODED_RESPONSE_HPP_
#define LIBSXG_SXG_ENCODED_RESPONSE_HPP_

#include <cstddef>

namespace sxg {

// Represents HTTP response header and payload.
// Header includes [:status, content-encoding, mi-sha256] parameters, and
// the payload is MICE encoded.
class EncodedResponse {
public:
  EncodedResponse() {}
  ~EncodedResponse() {}

  static EncodedResponse Encode(size_t mi_record_size,
                                const RawResponse& src);

  std::string GetHeaderIntegrity() const;

  size_t HeaderSize() const {
    return header_.Size();
  }

  const sxg::Header& GetHeader() const {
    return header_;
  }
  const std::string& GetPayload() const {
    return payload_;
  }

 private:
  Header header_;
  std::string payload_;
};

}  // namespace sxg

#endif  // LIBSXG_SXG_ENCODED_RESPONSE_HPP_