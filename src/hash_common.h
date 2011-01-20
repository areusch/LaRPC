/**
 * hash_common.h - Common functors for dealing with hash tables.
 * Copyright (C) 2010 Andrew Reusch <areusch@gmail.com>
 *
 */

#ifndef _HASH_COMMON_H
#define _HASH_COMMON_H

#include <string>

HASHTABLE_NAMESPACE_START

template <> struct hash< std::string > {
  bool operator()(const std::string& s) const {
    hash<const char*> h;
    return h(s.c_str());
  }
};

struct eqstr {
  bool operator()(const char* s1, const char* s2) const {
    return strcmp(s1,s2)==0;
  }
};

HASHTABLE_NAMESPACE_END

#endif // _HASH_COMMON_H


