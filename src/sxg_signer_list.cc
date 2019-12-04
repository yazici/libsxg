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

#include "libsxg/sxg_signer_list.hpp"

#include "openssl/evp.h"
#include "openssl/x509.h"

namespace sxg {

bool SignerList::AddEcdsaSigner(std::string name, uint64_t date,
                                uint64_t expires, std::string validity_url,
                                EVP_PKEY* private_key, X509* public_key,
                                std::string certificate_url) {
  signers_.emplace_back(name, date, expires, private_key, validity_url,
                        EcdsaCert(public_key, certificate_url));
  return true;
}

bool SignerList::AddEd25519Signer(std::string name, uint64_t date,
                                  uint64_t expires, std::string validity_url,
                                  EVP_PKEY* private_key, EVP_PKEY* public_key) {
  signers_.emplace_back(name, date, expires, private_key, validity_url,
                        Ed25519(public_key));
  return true;
}

}  // namespace sxg
