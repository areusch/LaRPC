/**
 * hash_set.h - LaRPC hash_set declarations.
 * Copyright (C) 2010 Andrew Reusch <areusch@gmail.com>
 *
 */

#ifndef _HASH_SET_H
#define _HASH_SET_H

#ifdef __GNUG__

#include <ext/hash_set>
namespace larpc {
  using __gnu_cxx::hash_set;
  using __gnu_cxx::hash;
};

#define HASHTABLE_NAMESPACE_START namespace __gnu_cxx {
#define HASHTABLE_NAMESPACE_END } // namespace __gnu_cxx

#else

#error "Unsupported compiler toolchain -- see hash_set.h"

#endif

#include "hash_common.h"

#endif // _HASH_SET_H


