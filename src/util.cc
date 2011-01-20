/**
 * util.cc - LaRPC utility functions.
 * Copyright (C) 2010 Andrew Reusch <areusch@gmail.com>
 *
 */

#include "util.h"
#include <stdio.h>
#include <openssl/evp.h>

namespace larpc {

namespace util {

string BoostEndpointToString(const tcp::endpoint& e) {
  char port_string[6];
  snprintf(port_string, 6, "%6d", e.port());
  return e.address().to_string() + ":" + port_string;
} 

} // namespace util

} // namespace larpc
