/**
 * openssl.cc - Desc
 * Copyright (C) 2011 Andrew Reusch <areusch@gmail.com>
 *
 */

#include "openssl.h"
#include <openssl/err.h>

#define OPENSSL_ERR_BUFFER_SIZE_BYTES  120

namespace larpc {

string GetSSLErrorString(unsigned long error_code) {
  char err_string[OPENSSL_ERR_BUFFER_SIZE_BYTES];

  ERR_error_string_n(error_code, err_string, OPENSSL_ERR_BUFFER_SIZE_BYTES);

  return string(err_string) + (!err_string[OPENSSL_ERR_BUFFER_SIZE_BYTES - 1] ? "..." : "");
}

} // namespace larpc
