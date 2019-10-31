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

#include "libsxg/sxg_header.hpp"

#include <algorithm>
#include <cstring>

namespace sxg {

void Header::Append(std::string key, std::string value) {
  std::transform(key.begin(), key.end(), key.begin(), ::tolower);
  auto it = header_.find(key);
  if (it != header_.end()) {
    it->second.emplace_back(value);
  } else {
    header_.insert(std::make_pair(key, std::vector<std::string>{value}));
  }
}

void Header::Append(std::string key, uint64_t num) {
  std::transform(key.begin(), key.end(), key.begin(), ::tolower);
  auto it = header_.find(key);
  std::string value = std::to_string(num);
  if (it != header_.end()) {
    it->second.emplace_back(value);
  } else {
    header_.insert(std::make_pair(key, std::vector<std::string>{value}));
  }
}

void Header::Merge(const Header& from) {
  // Not efficient way, we should not repeat find() and use
  // std::vector::reserve to precise expantion.
  for (const auto& it : from.header_) {
    for (const auto& value : it.second) {
      Append(it.first, value);
    }
  }
}

std::string Header::SerializeInCbor() const {
  std::vector<std::string> keys;
  keys.reserve(header_.size());
  for (const auto& it : header_) {
    keys.emplace_back(it.first);
  }
  std::sort(keys.begin(),
            keys.end(),
            [](const std::string& a, const std::string& b) {
              if (a.size() < b.size()) {
                return -1;
              } else if (a.size() > b.size()){
                return 1;
              } else {
                return std::strcmp(a.c_str(), b.c_str());
              }
            });
  const size_t header_byte_size = sxg_expected_cbor_header_serialized_size(keys.size());
  const uint8_t map_header = sxg_cbor_map_header(keys.size());
  std::string serialized(header_byte_size + 1);
  sxg_serialize_int(map_header, 1, serialized.data());
  sxg_serialize_int(size, header_byte_size, serialized.data() + 1);
  for (const auto& key : keys) {
  }
  return serialized;
}

}  // namespace sxg
