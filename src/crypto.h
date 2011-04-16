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
#include <openssl/x509_vfy.h>
#include "proto/larpc.pb.h"

namespace larpc {

using std::map;
using std::string;

class KeyStore;

class X509Name {
 public:
  typedef map<string,string> Map;

  X509Name();
  explicit X509Name(const Map& kv);
  explicit X509Name(X509_NAME* name);
  ~X509Name();

  bool Fill(X509_NAME* out_name) const;

  string& operator[](const string& k);

  int size() const;

  Map::iterator find(const string& key);

  Map::iterator begin();
  Map::iterator end();
 private:
  Map map_;
};

class CryptoInterface {

  // Secure Time function: should return seconds past the unix epoch.
  typedef time_t(*secure_time_fn)();

  secure_time_fn time_fn_;
  time_t last_generated_serial_;
 public:
  CryptoInterface(uint64_t last_generated_serial, secure_time_fn time_fn);

  bool GenerateKey(const proto::KeygenParameters& params, EVP_PKEY** out_key);

  bool EncryptBuffer(unsigned char* buffer,
                     int buffer_size_bytes,
                     const proto::EncryptionDescriptor& descriptor,
                     KeyStore* key_store,
                     unsigned char** out_encrypted_buffer,
                     size_t* out_buffer_size_bytes);

  bool PasswordEncryptBuffer(unsigned char* buffer,
                             size_t buffer_size_bytes,
                             const string& password,
                             const proto::EncryptionDescriptor& descriptor,
                             unsigned char** out_decrypted_buffer,
                             size_t* out_buffer_size_bytes);

  bool DecryptBuffer(unsigned char* buffer,
                     int buffer_size_bytes,
                     const proto::EncryptionDescriptor& descriptor,
                     KeyStore* key_store,
                     unsigned char** out_decrypted_buffer,
                     size_t* out_buffer_size_bytes);

  bool PasswordDecryptBuffer(unsigned char* buffer,
                             size_t buffer_size_bytes,
                             const string& password,
                             const proto::EncryptionDescriptor& descriptor,
                             unsigned char** out_decrypted_buffer,
                             size_t* out_buffer_size_bytes);


  static bool PublicKeyToPKCS8String(X509* x509, string* out_encoded_key);
  static bool PublicKeyToPKCS8String(EVP_PKEY* public_key, string* out_encoded_key);

  bool PrivateKeyToPKCS8String(EVP_PKEY* private_key, string* out_encoded_key);

  static bool X509ToString(X509* x509, string* out_encoded_cert);
  static bool X509FromString(const string& encoded_cert, X509** out_cert);

  static bool PublicKeyFromPKCS8String(const string& pkcs8, EVP_PKEY** out_key);
  bool PrivateKeyFromPKCS8String(const string& pkcs8, EVP_PKEY** out_key);

  X509* CreateCertificate(const X509Name& subject,
                          EVP_PKEY* subject_public_key,
                          int num_valid_days,
                          const X509Name& issuer,
                          EVP_PKEY* issuer_public_key,
                          EVP_PKEY* issuer_private_key);
};

class X509Verifier {
 public:
  X509Verifier();
  ~X509Verifier();

  int LoadTrustedCerts(BIO* b);
  int LoadUntrustedCerts(BIO* b);
  int LoadCRLs(BIO* b);

  int ExportTrustedCerts(BIO* b);
  int ExportUnrustedCerts(BIO* b);
  int ExportCRLs(BIO* b);

  void Clear();

  bool VerifyCertificate(X509* cert);

 private:
  X509* LoadCert(BIO* b);
  bool ExportCert(X509* x, BIO* b);

  X509_CRL* LoadCRL(BIO* b);
  bool ExportCRL(X509_CRL* x, BIO* b);

  X509_STORE* trusted_certs_;
  STACK_OF(X509)* untrusted_certs_;
  STACK_OF(X509_CRL)* crls_;

 };

} // namespace larpc

#endif // _CRYPTO_H


