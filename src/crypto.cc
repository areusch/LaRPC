/**
 * crypto.cc - LaRPC Encryption/Decryption Routines
 * Copyright (C) 2010 Andrew Reusch <areusch@gmail.com>
 *
 */

#include "crypto.h"
#include <glog/logging.h>
#include <openssl/bio.h>
#include <openssl/dsa.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include "constants.h"
#include "key.h"

namespace larpc {

CryptoInterface::CryptoInterface(uint64_t last_generated_serial,
                                 secure_time_fn time_fn) : 
    time_fn_(time_fn), last_generated_serial_(last_generated_serial) {}

bool CryptoInterface::GenerateKey(const KeygenParameters& params, EVP_PKEY** out_key) {
  EVP_PKEY_CTX* ctx;
  EVP_PKEY* key = NULL;
  
  int type_nid = OBJ_sn2nid(params.key_type().c_str());

  if (type_nid == EVP_PKEY_RSA || type_nid == EVP_PKEY_RSA2) {
    ctx = EVP_PKEY_CTX_new_id(type_nid, NULL);
    
    if(!ctx) {
      LOG(ERROR) << "Cannot initialize key generation context for a key of type "
                 << params.key_type();
      return false;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
      LOG(ERROR) << "Cannot initialize key generator for a key of type "
                 << params.key_type();
      EVP_PKEY_CTX_free(ctx);
      return false;
    }

    int num_bits = KEYGEN_RSA_DEFAULT_KEY_SIZE_BITS;

    if (params.has_num_bits()) {
      if (params.num_bits() > KEYGEN_RSA_KEY_SIZE_LIMIT_BITS) {
        LOG(ERROR) << "Key size is too large!";
        EVP_PKEY_CTX_free(ctx);
        return false;
      }
      num_bits = params.num_bits();
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, num_bits) <= 0) {
      LOG(ERROR) << "An error occurred when setting the number of bits in the key!";
      return false;
    }
  } else if (type_nid == EVP_PKEY_DSA || type_nid == EVP_PKEY_DSA1 ||
             type_nid == EVP_PKEY_DSA2 || type_nid == EVP_PKEY_DSA3 ||
             type_nid == EVP_PKEY_DSA4) {
    EVP_PKEY_CTX* param_ctx = EVP_PKEY_CTX_new_id(type_nid, NULL);
    if (!param_ctx) {
      LOG(ERROR) << "Cannot initialize a key context; out of memory?";
      return false;
    }

    if (EVP_PKEY_paramgen_init(param_ctx) <= 0) {
      LOG(ERROR) << "Cannot initialize a parameter generator for a key of type "
                 << params.key_type();
      EVP_PKEY_CTX_free(ctx);
      EVP_PKEY_CTX_free(param_ctx);
      return false;
    }

    int num_bits = KEYGEN_DSA_DEFAULT_KEY_SIZE_BITS;

    if (params.has_num_bits()) {
      if (params.num_bits() > KEYGEN_RSA_KEY_SIZE_LIMIT_BITS) {
        LOG(ERROR) << "Key size is too large!";
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_CTX_free(param_ctx);
        return false;
      }
      num_bits = params.num_bits();
    }

    if (!EVP_PKEY_CTX_set_dsa_paramgen_bits(param_ctx, num_bits)) {
      LOG(ERROR) << "Unexpectedly cannot set number of bits in DSA parameter generator";
      EVP_PKEY_CTX_free(ctx);
      EVP_PKEY_CTX_free(param_ctx);
      return false;
    }

    EVP_PKEY* param_key = EVP_PKEY_new();
    if (!EVP_PKEY_paramgen(param_ctx, &param_key)) {
      LOG(ERROR) << "Cannot generate parameters for DSA key generation!";
      EVP_PKEY_CTX_free(ctx);
      EVP_PKEY_CTX_free(param_ctx);
      return false;
    }      

    ctx = EVP_PKEY_CTX_new(param_key, NULL);

    if(!ctx) {
      LOG(ERROR) << "Cannot initialize key generation context for a key of type "
                 << params.key_type();
      return false;
    }


    if (EVP_PKEY_keygen_init(ctx) <= 0) {
      LOG(ERROR) << "Cannot initialize key generator for a key of type "
                 << params.key_type();
      EVP_PKEY_CTX_free(ctx);
      return false;
    }
  } else {
    LOG(WARNING) << "Don't know of any parameters for a key of type "
                 << params.key_type() << "; trying to blindly generate key! "
                 << "This may create insecure keys!";
  }

  if (EVP_PKEY_keygen(ctx, &key) <= 0) {
    LOG(ERROR) << "An error occurred while generating a key of type "
               << params.key_type();
    EVP_PKEY_CTX_free(ctx);
    return false;
  }

  *out_key = key;
  EVP_PKEY_CTX_free(ctx);
  return true;
}

bool CryptoInterface::DecryptBuffer(unsigned char* buffer,
                   int buffer_size_bytes,
                   const EncryptionDescriptor& descriptor,
                   KeyStore* key_store,
                   unsigned char** out_decrypted_buffer,
                   size_t* out_buffer_size_bytes) {
  if (descriptor.is_password_based()) {
    return PasswordDecryptBuffer(buffer,
                                 buffer_size_bytes,
                                 "",
                                 descriptor,
                                 out_decrypted_buffer,
                                 out_buffer_size_bytes);
  }

  // Asymmetric decryption
  EVP_PKEY* public_key = key_store->Get(descriptor.key_hash());
  if (!public_key) {
    LOG(ERROR) << "Public Key " << descriptor.key_hash() 
               << " not found; cannot decrypt buffer!";
    return false;
  }

  int public_key_type = EVP_PKEY_type(public_key->type);
  if (public_key_type == NID_undef) {
    LOG(ERROR) << "Cannot determine type of this public key!";
    return false;
  }

  ENGINE* engine = ENGINE_get_cipher_engine(public_key_type);
  if (!engine) {
    LOG(ERROR) << "Cannot load an appropriate crypto engine!";
    return false;
  }

  if (!ENGINE_init(engine)) {
    LOG(ERROR) << "Error initializing crypto engine!";
    return false;
  }

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(public_key, engine);
  if (!ctx) {
    LOG(ERROR) << "Cannot allocate decryption context!";
    ENGINE_finish(engine);
    return false;
  }

  if (!EVP_PKEY_decrypt_init(ctx) <= 0) {
    LOG(ERROR) << "Cannot init decryption context!";
    EVP_PKEY_CTX_free(ctx);
    ENGINE_finish(engine);
    return false;
  }

  size_t out_bufsize;
  if (!EVP_PKEY_decrypt(ctx, NULL, &out_bufsize, buffer, buffer_size_bytes)) {
    LOG(ERROR) << "Cannot compute decrypted buffer size!";
    EVP_PKEY_CTX_free(ctx);
    ENGINE_finish(engine);
    return false;
  }

  uint8_t* decrypted_buffer = new uint8_t[out_bufsize];
  if (!EVP_PKEY_decrypt(ctx, 
                        decrypted_buffer, 
                        &out_bufsize, 
                        buffer, 
                        buffer_size_bytes)) {
    LOG(ERROR) << "Cannot decrypt buffer!";
    EVP_PKEY_CTX_free(ctx);
    ENGINE_finish(engine);
    return false;
  }

  EVP_PKEY_CTX_free(ctx);
  ENGINE_finish(engine);

  *out_decrypted_buffer = decrypted_buffer;
  *out_buffer_size_bytes = out_bufsize;
}

bool CryptoInterface::PasswordDecryptBuffer(unsigned char* buffer,
                           size_t buffer_size_bytes,
                           const string& password,
                           const EncryptionDescriptor& descriptor,
                           unsigned char** out_decrypted_buffer,
                           size_t* out_buffer_size_bytes) {
  const EVP_CIPHER* cipher = EVP_get_cipherbyname(descriptor.cipher().c_str());
  if (!cipher) {
    LOG(ERROR) << "Invalid cipher: " << descriptor.cipher();
    return false;
  }

  const EVP_MD* digest = EVP_get_digestbyname(
    descriptor.password_digest_algorithm().c_str());
  if (!digest) {
    LOG(ERROR) << "Invalid digest: " << descriptor.password_digest_algorithm();
    return false;
  }

  unsigned char evp_key[EVP_MAX_KEY_LENGTH] = {'\0'};
  unsigned char evp_iv[EVP_MAX_IV_LENGTH] = {'\0'};

  int key_length = EVP_BytesToKey(cipher, 
                                  digest, 
                                  NULL, 
                                  (const unsigned char*) password.c_str(), 
                                  password.length(),
                                  EVP_BYTESTOKEY_COUNT,
                                  evp_key,
                                  evp_iv);

  if (!key_length)
    return false;

  EVP_CIPHER_CTX ctx;
  EVP_CIPHER_CTX_init(&ctx);

  if (!EVP_DecryptInit(&ctx, cipher, evp_key, evp_iv)) {
    LOG(ERROR) << "Could not init decryption!";
    EVP_CIPHER_CTX_cleanup(&ctx);
    return false;
  }

  EVP_CIPHER_CTX_set_key_length(&ctx, key_length);

  int decrypted_buffer_length = key_length + buffer_size_bytes; 
  unsigned char* evp_decrypted_buffer = 
    new unsigned char[decrypted_buffer_length];

  if (!EVP_DecryptUpdate(&ctx, 
                         (unsigned char*) evp_decrypted_buffer,
                         &decrypted_buffer_length,
                         buffer,
                         buffer_size_bytes)) {
    LOG(ERROR) << "Error while decrypting buffer!";
    EVP_CIPHER_CTX_cleanup(&ctx);
    return false;
  }

  if (!EVP_DecryptFinal(&ctx,
                        evp_decrypted_buffer,
                        &decrypted_buffer_length)) {
    LOG(ERROR) << "Error finalizing decryption; check padding!";
    EVP_CIPHER_CTX_cleanup(&ctx);
    return false;
  }

  *out_decrypted_buffer = evp_decrypted_buffer;
}

bool CryptoInterface::EncryptBuffer(unsigned char* buffer,
                   int buffer_size_bytes,
                   const EncryptionDescriptor& descriptor,
                   KeyStore* key_store,
                   unsigned char** out_encrypted_buffer,
                   size_t* out_buffer_size_bytes) {
  if (descriptor.is_password_based()) {
    return PasswordEncryptBuffer(buffer,
                                 buffer_size_bytes,
                                 "",
                                 descriptor,
                                 out_encrypted_buffer,
                                 out_buffer_size_bytes);
  }

  // Asymmetric decryption
  EVP_PKEY* private_key = key_store->Get(descriptor.key_hash());
  if (!private_key) {
    LOG(ERROR) << "Private Key " << descriptor.key_hash() 
               << " not found; cannot decrypt buffer!";
    return false;
  }

  int private_key_type = EVP_PKEY_type(private_key->type);
  if (private_key_type == NID_undef) {
    LOG(ERROR) << "Cannot determine type of this public key!";
    return false;
  }

  ENGINE* engine = ENGINE_get_cipher_engine(private_key_type);
  if (!engine) {
    LOG(ERROR) << "Cannot load an appropriate crypto engine!";
    return false;
  }

  if (!ENGINE_init(engine)) {
    LOG(ERROR) << "Error initializing crypto engine!";
    ENGINE_finish(engine);
    return false;
  }

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(private_key, engine);
  if (!ctx) {
    LOG(ERROR) << "Cannot allocate decryption context!";
    ENGINE_finish(engine);
    return false;
  }

  if (!EVP_PKEY_encrypt_init(ctx) <= 0) {
    LOG(ERROR) << "Cannot init decryption context!";
    EVP_PKEY_CTX_free(ctx);
    ENGINE_finish(engine);
    return false;
  }

  size_t out_bufsize;
  if (!EVP_PKEY_encrypt(ctx, NULL, &out_bufsize, buffer, buffer_size_bytes)) {
    LOG(ERROR) << "Cannot compute decrypted buffer size!";
    EVP_PKEY_CTX_free(ctx);
    ENGINE_finish(engine);
    return false;
  }

  uint8_t* encrypted_buffer = new uint8_t[out_bufsize];
  if (!EVP_PKEY_encrypt(ctx, 
                        encrypted_buffer, 
                        &out_bufsize, 
                        buffer, 
                        buffer_size_bytes)) {
    LOG(ERROR) << "Cannot decrypt buffer!";
    EVP_PKEY_CTX_free(ctx);
    ENGINE_finish(engine);
    return false;
  }

  EVP_PKEY_CTX_free(ctx);
  ENGINE_finish(engine);
  *out_encrypted_buffer = encrypted_buffer;
  *out_buffer_size_bytes = out_bufsize;
}

bool CryptoInterface::PasswordEncryptBuffer(unsigned char* buffer,
                           size_t buffer_size_bytes,
                           const string& password,
                           const EncryptionDescriptor& descriptor,
                           unsigned char** out_encrypted_buffer,
                           size_t* out_buffer_size_bytes) {
  const EVP_CIPHER* cipher = EVP_get_cipherbyname(descriptor.cipher().c_str());
  if (!cipher) {
    LOG(ERROR) << "Invalid cipher: " << descriptor.cipher();
    return false;
  }

  const EVP_MD* digest = EVP_get_digestbyname(
    descriptor.password_digest_algorithm().c_str());
  if (!digest) {
    LOG(ERROR) << "Invalid digest: " << descriptor.password_digest_algorithm();
    return false;
  }

  unsigned char evp_key[EVP_MAX_KEY_LENGTH] = {'\0'};
  unsigned char evp_iv[EVP_MAX_IV_LENGTH] = {'\0'};

  int key_length = EVP_BytesToKey(cipher, 
                                  digest, 
                                  NULL, 
                                  (const unsigned char*) password.c_str(), 
                                  password.length(),
                                  EVP_BYTESTOKEY_COUNT,
                                  evp_key,
                                  evp_iv);

  if (!key_length)
    return false;

  EVP_CIPHER_CTX ctx;
  EVP_CIPHER_CTX_init(&ctx);

  if (!EVP_EncryptInit(&ctx, cipher, evp_key, evp_iv)) {
    LOG(ERROR) << "Could not init decryption!";
    EVP_CIPHER_CTX_cleanup(&ctx);
    return false;
  }

  EVP_CIPHER_CTX_set_key_length(&ctx, key_length);

  int encrypted_buffer_length = key_length + buffer_size_bytes; 
  unsigned char* evp_encrypted_buffer = 
    new unsigned char[encrypted_buffer_length];

  if (!EVP_EncryptUpdate(&ctx, 
                         evp_encrypted_buffer,
                         &encrypted_buffer_length,
                         buffer,
                         buffer_size_bytes)) {
    LOG(ERROR) << "Error while decrypting buffer!";
    EVP_CIPHER_CTX_cleanup(&ctx);
    return false;
  }

  if (!EVP_EncryptFinal(&ctx,
                        evp_encrypted_buffer,
                        &encrypted_buffer_length)) {
    LOG(ERROR) << "Error finalizing decryption; check padding!";
    EVP_CIPHER_CTX_cleanup(&ctx);
    return false;
  }

  *out_encrypted_buffer = evp_encrypted_buffer;
}

typedef int(*ExtractFunction)(BIO*, void*);

static bool PEMSerialize(ExtractFunction extract_fn, 
                         void* obj, 
                         string* out_encoded_data) {
  BIO* buf_bio = BIO_new(BIO_s_mem());

  if (!extract_fn(buf_bio, obj)) {
    LOG(ERROR) << "Cannot serialize data!";
    return false;
  }

  char* buf;
  long str_length = BIO_get_mem_data(buf_bio, &buf);
  CHECK(str_length > 0) << "Serialized data is of 0 length!";

  out_encoded_data->assign(buf, str_length);
  BIO_free(buf_bio);

  return true;
}

bool CryptoInterface::PublicKeyToPKCS8String(X509* x509, string* out_encoded_key) {
  CHECK_NOTNULL(x509);
  CHECK_NOTNULL(out_encoded_key);

  EVP_PKEY* public_key = X509_get_pubkey(x509);
  CHECK_NOTNULL(public_key);

  return PublicKeyToPKCS8String(public_key, out_encoded_key);
}

bool CryptoInterface::PublicKeyToPKCS8String(EVP_PKEY* public_key, string* out_encoded_key) {
  CHECK_NOTNULL(public_key);
  CHECK_NOTNULL(out_encoded_key);

  return PEMSerialize((ExtractFunction) &PEM_write_bio_PUBKEY,
                      public_key,
                      out_encoded_key);
}

bool CryptoInterface::X509ToString(X509* x509, string* out_encoded_cert) {
  CHECK_NOTNULL(x509);
  CHECK_NOTNULL(out_encoded_cert);

  return PEMSerialize((ExtractFunction) &PEM_write_bio_X509,
                      x509,
                      out_encoded_cert);
}

bool CryptoInterface::PublicKeyFromPKCS8String(const string& pkcs8, EVP_PKEY** out_key) {
  BIO* b = BIO_new_mem_buf((void*) pkcs8.c_str(), pkcs8.length());

  if (!PEM_read_bio_PUBKEY(b, out_key, NULL, NULL)) {
    BIO_free(b);
    return false;
  }

  BIO_free(b);
  return true;
}

bool CryptoInterface::PrivateKeyFromPKCS8String(const string& pkcs8, EVP_PKEY** out_key) {
  BIO* b = BIO_new_mem_buf((void*) pkcs8.c_str(), pkcs8.length());

  if (!PEM_read_bio_PrivateKey(b, out_key, NULL, NULL)) {
    BIO_free(b);
    return false;
  }

  BIO_free(b);
  return true;
}

bool CryptoInterface::PrivateKeyToPKCS8String(EVP_PKEY* private_key, string* out_encoded_key) {
  BIO* b = BIO_new(BIO_s_mem());

  if (!PEM_write_bio_PrivateKey(b, private_key, NULL, NULL, 0, NULL, NULL)) {
    BIO_free(b);
    return false;
  }

  char* buf_start;
  int buf_size = BIO_get_mem_data(b, &buf_start);
  out_encoded_key->assign(buf_start, buf_size);
  
  BIO_free(b);
  return true;
}

static bool BuildX509Name(const map<string,string>& kv, X509_NAME* out_name) {
  for (map<string,string>::const_iterator it = kv.begin();
       it != kv.end();
       ++it) {
    if (!X509_NAME_add_entry_by_txt(out_name, 
                                    (*it).first.c_str(),
                                    MBSTRING_ASC, 
                                    (const unsigned char*) (*it).second.c_str(),
                                    -1,
                                    -1,
                                    0)) {
      LOG(ERROR) << "Bad key-value pair in X509 Name: " << 
        (*it).first << "=" << 
        (*it).second;

      return false;
    }
  }

  return true;
}

X509* CryptoInterface::CreateCertificate(const map<string,string>& subject,
                                         EVP_PKEY* subject_public_key,
                                         int num_valid_days,
                                         const map<string,string>& issuer, 
                                         EVP_PKEY* issuer_public_key,
                                         EVP_PKEY* issuer_private_key) {
  X509* cert = X509_new();

  if (!cert) {
    LOG(ERROR) << "Cannot create new X.509 certificate! Out of memory?";
    return NULL;
  }

  time_t now_unix_ts = time_fn_();
  if (!now_unix_ts) {
    LOG(ERROR) << "Invalid timestamp returned by secure time function..."
               << "Secure time function is insecure :(";
    X509_free(cert);
    return NULL;
  }

  if (!X509_set_version(cert, 2) ||
      !ASN1_INTEGER_set(X509_get_serialNumber(cert), ++last_generated_serial_) ||
      !X509_gmtime_adj(X509_get_notBefore(cert), now_unix_ts) ||
      !X509_gmtime_adj(X509_get_notAfter(cert), now_unix_ts + (long)60*60*24*num_valid_days) ||
      !X509_set_pubkey(cert, subject_public_key) ||
      
      !BuildX509Name(subject, X509_get_subject_name(cert)) ||
      !BuildX509Name(issuer, X509_get_issuer_name(cert))) {
    
    LOG(ERROR) << "Cannot construct certificate!";
    X509_free(cert);
    return NULL;
  }
  
  if (!X509_sign(cert, issuer_private_key, EVP_sha1())) {
    LOG(ERROR) << "Cannot sign certificate!";
    X509_free(cert);
    return NULL;
  }

  return cert;
}

} // namespace larpc
