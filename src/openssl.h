/**
 * openssl.h - LaRPC defines for OpenSSL.
 * Copyright (C) 2011 Andrew Reusch <areusch@gmail.com>
 *
 */

#ifndef _SRC_OPENSSL_H
#define _SRC_OPENSSL_H

#include <string>

namespace larpc {

using ::std::string;

string GetSSLErrorString(unsigned long error_code);

} // namespace larpc

#endif // _SRC_OPENSSL_H


