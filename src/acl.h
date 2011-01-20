/**
 * acl.h - LaRPC ACLs.
 * Copyright (C) 2010 Andrew Reusch <areusch@gmail.com>
 *
 */

#ifndef _ACL_H
#define _ACL_H

#include <string>
#include "hash_map.h"

namespace larpc {
class ActionSpecifier;
}

HASHTABLE_NAMESPACE_START
template <> struct hash<larpc::ActionSpecifier>;
HASHTABLE_NAMESPACE_END

namespace larpc {

class Principle;
class ACL;

using std::string;

class ActionSpecifier {
 public:
  ActionSpecifier(Principle* principle, 
                  const string& object,
                  const string& action);

  bool operator==(const ActionSpecifier& other) const;

 private:
  Principle* principle_;
  string object_;
  string action_;

  friend class ACL;
  friend struct hash<ActionSpecifier>;
};

} // namespace larpc

HASHTABLE_NAMESPACE_START
template <> 
struct hash<larpc::ActionSpecifier> {
 public:
  long operator()(const larpc::ActionSpecifier& a) const {
    return long(a.principle_) + 
      hash<const char*>()(a.object_.c_str()) + 
      hash<const char*>()(a.action_.c_str());
  }
};
HASHTABLE_NAMESPACE_END

namespace larpc {

class ACL {
  typedef hash_map<ActionSpecifier,bool,hash<ActionSpecifier> > AclHashMap;

 public:
  ACL(Principle* principle);

  void SetAccess(const ActionSpecifier& action, bool granted);
  bool IsAccessGranted(const ActionSpecifier& action);

 private:
  Principle* principle_;
  AclHashMap acl_;
};

} // namespace larpc

#endif // _ACL_H

