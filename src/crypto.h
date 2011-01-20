/**
 * crypto.h - LaRPC Encryption/Decryption Routines
 * Copyright (C) 2010 Andrew Reusch <areusch@gmail.com>
 *
 */

#ifndef _CRYPTO_H
#define _CRYPTO_H

#include <map>
#include <string>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include "proto/larpc.pb.h"

namespace larpc { 

using std::map;
using std::string;

class KeyStore;

class CryptoInterface {

  // Secure Time function: should return seconds past the unix epoch.
  typedef time_t(*secure_time_fn)();

  secure_time_fn time_fn_;
  time_t last_generated_serial_;
 public:
  CryptoInterface(uint64_t last_generated_serial, secure_time_fn time_fn);

  bool GenerateKey(const KeygenParameters& params, EVP_PKEY** out_key);
  
  bool EncryptBuffer(unsigned char* buffer,
                     int buffer_size_bytes,
                     const EncryptionDescriptor& descriptor,
                     KeyStore* key_store,
                     unsigned char** out_encrypted_buffer,
                     size_t* out_buffer_size_bytes);

  bool PasswordEncryptBuffer(unsigned char* buffer,
                             size_t buffer_size_bytes,
                             const string& password,
                             const EncryptionDescriptor& descriptor,
                             unsigned char** out_decrypted_buffer,
                             size_t* out_buffer_size_bytes);

  bool DecryptBuffer(unsigned char* buffer,
                     int buffer_size_bytes,
                     const EncryptionDescriptor& descriptor,
                     KeyStore* key_store,
                     unsigned char** out_decrypted_buffer,
                     size_t* out_buffer_size_bytes);

  bool PasswordDecryptBuffer(unsigned char* buffer,
                             size_t buffer_size_bytes,
                             const string& password,
                             const EncryptionDescriptor& descriptor,
                             unsigned char** out_decrypted_buffer,
                             size_t* out_buffer_size_bytes);


  static bool PublicKeyToPKCS8String(X509* x509, string* out_encoded_key);
  static bool PublicKeyToPKCS8String(EVP_PKEY* public_key, string* out_encoded_key);

  bool PrivateKeyToPKCS8String(EVP_PKEY* private_key, string* out_encoded_key);

  static bool X509ToString(X509* x509, string* out_encoded_cert);

  static bool PublicKeyFromPKCS8String(const string& pkcs8, EVP_PKEY** out_key);
  bool PrivateKeyFromPKCS8String(const string& pkcs8, EVP_PKEY** out_key);

  X509* CreateCertificate(const map<string,string>& subject,
                          EVP_PKEY* subject_public_key,
                          int num_valid_days,
                          const map<string,string>& issuer,
                          EVP_PKEY* issuer_public_key,
                          EVP_PKEY* issuer_private_key);
};
} // namespace larpc

#endif // _CRYPTO_H


