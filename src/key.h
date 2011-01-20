/**
 * key.h - LaRPC cryptography functions
 * Copyright (C) 2010 Andrew Reusch <areusch@gmail.com>
 *
 */

#ifndef _KEY_H
#define _KEY_H

#include <set>
#include <string>
#include <glog/logging.h>
#include <openssl/evp.h>
#include "hash_map.h"

namespace larpc {

using std::set;
using std::string;

class KeyStore {
 public:
  typedef hash_map<string, EVP_PKEY*, hash<string> > KeyMap;

  KeyStore();
  ~KeyStore();

  void Add(EVP_PKEY* key);
  void AddTrusted(EVP_PKEY* key);

  EVP_PKEY* Get(const string& key);

  void Remove(EVP_PKEY* key);
  void Revoke(EVP_PKEY* key);
 private:
  KeyMap keys_;
  set<EVP_PKEY*> trusted_keys_;
};

} // namespace larpc

#endif // _KEY_H


