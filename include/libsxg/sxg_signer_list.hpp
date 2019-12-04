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

#include <cstdint>
#include <string>
#include <vector>
#include <iostream>

#include <openssl/evp.h>
#include <openssl/x509.h>

namespace sxg {

struct EcdsaCert {
  X509* certificate;
  std::string certificate_url;
  EcdsaCert() : certificate(nullptr) {}
  EcdsaCert(X509* cert, const std::string& url)
    : certificate(cert), certificate_url(url) {
    X509_up_ref(certificate);
  }
  EcdsaCert(const EcdsaCert& o)
    : certificate(o.certificate), certificate_url(o.certificate_url) {
    X509_up_ref(certificate);
  }
  EcdsaCert(EcdsaCert&& o)
    : certificate(o.certificate), certificate_url(o.certificate_url) {
    o.certificate = nullptr;
    o.certificate_url = "";
  }
  EcdsaCert& operator=(const EcdsaCert& rhs) {
    certificate = rhs.certificate;
    certificate_url = rhs.certificate_url;
    X509_up_ref(certificate);
    return *this;
  }
  ~EcdsaCert() {
    X509_free(certificate);
  }
};

struct Ed25519 {
  EVP_PKEY* public_key;
  Ed25519() : public_key(nullptr) {}
  Ed25519(Ed25519&& o) : public_key(o.public_key) {
    o.public_key = nullptr;
  }
  Ed25519(EVP_PKEY* key) : public_key(key) {
    EVP_PKEY_up_ref(public_key);
  }
  ~Ed25519() {
    EVP_PKEY_free(public_key);
  }
};

struct Signer {
  std::string name;
  uint64_t date;
  uint64_t expires;
  EVP_PKEY* private_key;
  std::string validity_url;
  enum signer_algorithm {
    SXG_ECDSA,
    SXG_ED25519,
  } type;
  EcdsaCert ecdsa;
  Ed25519 ed25519;
  Signer(const Signer&) = delete;
  Signer(Signer&&) = default;
  Signer& operator=(const Signer&) = delete;
  Signer(std::string n, uint64_t d, uint64_t e, EVP_PKEY* pk, std::string vu,
         EcdsaCert&& ec)
    : name(n), date(d), expires(e), private_key(pk),
      validity_url(vu), type(SXG_ECDSA), ecdsa(std::move(ec)) {
    EVP_PKEY_up_ref(private_key);
  }
  Signer(std::string n, uint64_t d, uint64_t e, EVP_PKEY* pk, std::string vu,
         Ed25519&& ed)
    : name(n), date(d), expires(e), private_key(pk),
      validity_url(vu), type(SXG_ED25519), ed25519(std::move(ed)) {
    EVP_PKEY_up_ref(private_key);
  }
  ~Signer() {
    EVP_PKEY_free(private_key);
  }
};

class SignerList {
public:
  // Appends new ecdsa signer to signer list.
  // Increments the reference count of private_key & public_key.
  // Returns true on success.
  bool AddEcdsaSigner(std::string name, uint64_t date, uint64_t expires,
                      std::string validity_url, EVP_PKEY* private_key,
                      X509* public_key, std::string certificate_url);

  // Appends new Ed25519 signer to signer list.
  // Increments the reference count of private_key & public_key.
  // Returns true on success.
  // Note: Ed25519 signer does not use certificates, then Ed25519 signer does
  // not require certificate_url.
  bool AddEd25519Signer(std::string name, uint64_t date, uint64_t expires,
                        std::string validity_url, EVP_PKEY* private_key,
                        EVP_PKEY* public_key);

private:
  std::vector<Signer> signers_;
};

}  // namespace sxg

#endif  // LIBSXG_SXG_SIGNER_LISTS_HPP_
