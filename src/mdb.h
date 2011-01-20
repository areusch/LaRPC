/**
 * mdb.h - LaRPC Machine Database
 * Copyright (C) 2010 Andrew Reusch <areusch@gmail.com>
 *
 */

#ifndef _MDB_H
#define _MDB_H

#include <string>
#include <vector>
#include <openssl/evp.h>
#include "hash_set.h"
#include "principle.h"

namespace larpc {

using ::std::string;
using ::std::vector;

class MachineDatabase {
 public:
  static MachineDatabase* FromDataFile(const string& path);

  /**
   * Construct a new, empty machine database.
   */
  MachineDatabase();
  ~MachineDatabase();
  
  uint32_t GenerateNonce(EVP_PKEY* remote_machine_key, uint32_t provided_nonce);

  bool VerifyPrinciples(EVP_PKEY* remote_machine_key,
                        vector<Principle> remote_principles,
                        uint32_t remote_nonce);

 private:
  hash_set<EVP_PKEY*> machines_;
};

} // namespace larpc

#endif // _MDB_H


