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

namespace sxg {

void Header::Append(std::string key, std::string value) {
  auto it = header_.find(key);
  if (it != header_.end()) {
    it->second.emplace_back(value);
  } else {
    header_.insert(std::make_pair(key, std::vector<std::string>(value)}));
  }
}

void Header::Append(std::string key, uint64_t num) {
  auto it = header_.find(key);
  std::string value = std::to_string(num);
  if (it != header_.end()) {
    it->second.emplace_back(value);
  } else {
    header_.insert(std::make_pair(key, std::vector<std::string>(value)}));
  }
}

void Header::Merge(const Header& from) {
  // Not efficient way, we should not repeat find() and use
  // std::vector::reserve to precise expantion.
  for (const auto& it : from) {
    for (const auto& value : it.second) {
      Append(it.first, value);
    }
  }
}

}  // namespace sxg
