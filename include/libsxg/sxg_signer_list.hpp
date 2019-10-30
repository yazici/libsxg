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

#ifndef LIBSXG_SXG_SIGNER_LIST_HPP_
#define LIBSXG_SXG_SIGNER_LIST_HPP_

#include <openssl/evp.h>
#include <openssl/x509.h>

namespace sxg {

struct EcdsaCert {
  X509* public_key;
  char* certificate_url;
};

struct Ed25519 {
  EVP_PKEY* public_key;
};

struct Signer {
  std::string name_;
  time_t date;
  time_t expires;
  EVP_PKEY* private_key;
  std::string validity_url;
  enum signer_algorithm {
    SXG_ECDSA,
    SXG_ED25519,
  } type;
  union Cert {
    EcdsaCert ecdsa;
    Ed25519 ed25519;
  } public_key;
};

class SignerList {
public:
  // Appends new ecdsa signer to signer list.
  // Increments the reference count of private_key & public_key.
  void AddEcdsaSigner(std::string name, uint64_t date, uint64_t expires,
                      std::string validity_url, EVP_PKEY* private_key,
                      X509* public_key, std::string certificate_url);

  // Appends new Ed25519 signer to signer list.
  // Increments the reference count of private_key & public_key.
  // Note: Ed25519 signer does not use certificates, then Ed25519 signer does
  // not require certificate_url.
  void AddEd25519Signer(std::string name, uint64_t date, uint64_t expires,
                        std::string validity_url, EVP_PKEY* private_key,
                        EVP_PKEY* public_key);

private:
  std::vector<Signer> signers_;
};

}  // namespace sxg

#endif  // LIBSXG_SXG_SIGNER_LISTS_HPP_
