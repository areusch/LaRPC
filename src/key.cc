/**
 * key.cc - LaRPC cryptography
 * Copyright (C) 2010 Andrew Reusch <areusch@gmail.com>
 *
 */

#include "key.h"
#include <memory>

namespace larpc {

KeyStore::KeyStore() {}

KeyStore::~KeyStore() {}

EVP_PKEY* KeyStore::Get(const string& key) {
  KeyMap::iterator it = keys_.find(key);
  if (it != keys_.end())
    return (*it).second;

  return NULL;
}

} // namespace larpc
