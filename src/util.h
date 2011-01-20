/**
 * util.h - LaRPC utility functions.
 * Copyright (C) 2010 Andrew Reusch <areusch@gmail.com>
 *
 */

#ifndef _UTIL_H
#define _UTIL_H

#include <boost/asio.hpp>
#include <string>
#include "proto/larpc.pb.h"

#define DISALLOW_EVIL_CONSTRUCTORS(x)           \
  x(const x& other);                            \
  x& operator=(const x& other);

namespace larpc {

namespace util {

using ::boost::asio::ip::tcp;
using ::std::string;

string BoostEndpointToString(const tcp::endpoint& e);

} // namespace util
} // namespace larpc

#endif // _UTIL_H


