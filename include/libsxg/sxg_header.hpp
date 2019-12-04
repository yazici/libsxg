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

#ifndef LIBSXG_SXG_HEADER_HPP_
#define LIBSXG_SXG_HEADER_HPP_

#include <cstdint>
#include <string>
#include <unordered_map>

namespace sxg {

// Innner HTTP headers of SXG.
class Header {
public:
  void Append(std::string key, std::string value);
  void Append(std::string key, uint64_t num);
  void Merge(const Header& from);
  size_t Size() const {
    return header_.size();
  }

private:
  std::unordered_map<std::string, std::vector<std::string>> header_;
};

}  // namespace sxg

#endif  // LIBSXG_SXG_HEADER_HPP_
