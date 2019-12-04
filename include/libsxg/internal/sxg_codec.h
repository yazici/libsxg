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

#ifndef LIBSXG_INTERNAL_SXG_CODEC_H_
#define LIBSXG_INTERNAL_SXG_CODEC_H_

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdbool.h>

#include "libsxg/sxg_buffer.h"

#ifdef __cplusplus
extern "C" {
#endif

// Replaces contents of `dst` with SHA-hash of `src`. Returns true on success.
bool sxg_calc_sha256(const sxg_buffer_t* src, sxg_buffer_t* dst);
bool sxg_calc_sha384(const sxg_buffer_t* src, sxg_buffer_t* dst);

// Returns size of expected buffer length to input size.
size_t sxg_estimated_base64_size(const size_t size);

// Write memory
bool sxg_base64encode_write(const uint8_t* src, size_t length, char* target);

// Appends base64 of `src` to `dst`. Returns true on success.
bool sxg_base64encode(const sxg_buffer_t* src, sxg_buffer_t* dst);

// Appends base64 of byte array to `dst`. Returns true on success.
bool sxg_base64encode_bytes(const uint8_t* src, size_t length,
                            sxg_buffer_t* dst);

size_t sxg_estimated_mi_sha256_size(const size_t length,
                                    const uint64_t record_size);

size_t sxg_estimated_mi_sha256_remainder_size(size_t size,
                                              uint64_t record_size);

void sxg_encode_mi_sha256_write(const char* src, size_t size,
                                uint64_t record_size, char* dst, char* proof);

// Replaces `encoded` and `proof` with Merkle Integrity Content Encoding(MICE)
// of `src`. Returns true on success.
bool sxg_encode_mi_sha256(const sxg_buffer_t* src, uint64_t record_size,
                          sxg_buffer_t* encoded,
                          uint8_t proof[SHA256_DIGEST_LENGTH]);

// Replaces `dst` with SHA256 of `cert`. Returns true on success.
bool sxg_calculate_cert_sha256(X509* cert, sxg_buffer_t* dst);

// Replaces `dst` with signature of `src`. Returns true on success.
bool sxg_evp_sign(EVP_PKEY* private_key, const sxg_buffer_t* src,
                  sxg_buffer_t* dst);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // LIBSXG_INTERNAL_SXG_CODEC_H_
