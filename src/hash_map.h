/**
 * hash_map.h - LaRPC hash_map declarations.
 * Copyright (C) 2010 Andrew Reusch <areusch@gmail.com>
 *
 */

#ifndef _HASH_MAP_H
#define _HASH_MAP_H

#ifdef __GNUG__

#include <ext/hash_map>
namespace larpc {
  using __gnu_cxx::hash_map;
  using __gnu_cxx::hash;
};

#define HASHTABLE_NAMESPACE_START namespace __gnu_cxx {
#define HASHTABLE_NAMESPACE_END } // namespace __gnu_cxx

#else

#error "Unsupported compiler toolchain -- see hash_map.h"

#endif

#include "hash_common.h"

#endif // _HASH_MAP_H


