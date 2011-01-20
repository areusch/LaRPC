/**
 * mdb.cc - LaRPC Machine Database
 * Copyright (C) 2010 Andrew Reusch <areusch@gmail.com>
 *
 */

#include "mdb.h"
#include <openssl/lhash.h>

namespace larpc {

MachineDatabase::MachineDatabase() {}

MachineDatabase::~MachineDatabase() {}

uint32_t MachineDatabase::GenerateNonce(EVP_PKEY* remote_machine_key,
                                        uint32_t provided_nonce) {
  return 0;
}

} // namespace larpc
