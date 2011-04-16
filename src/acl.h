/**
 * acl.h - LaRPC ACLs.
 * Copyright (C) 2010 Andrew Reusch <areusch@gmail.com>
 *
 */

#ifndef _ACL_H
#define _ACL_H

#include <string>
#include <map>
#include "hash_map.h"
#include <openssl/x509.h>
#include "identity.h"
#include "proto/larpc.pb.h"
#include "principle.h"

namespace larpc {
class ActionSpecifier;
}

HASHTABLE_NAMESPACE_START
template <> struct hash<larpc::ActionSpecifier>;
HASHTABLE_NAMESPACE_END

namespace larpc {

class Principle;
class ACL;

using std::map;
using std::string;

class ActionSpecifier {
 public:
  ActionSpecifier(Principle* principle,
                  const string& object,
                  const string& action);

  bool operator==(const ActionSpecifier& other) const;

  bool FillIdentityMap(map<string,string>* out_map) const;

 private:
  Identity* entity_;
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
    return a.entity_->Hash();
  }
};

HASHTABLE_NAMESPACE_END

namespace larpc {

class ACLEntry {
 public:
  static ACLEntry* Create(Principle* principle,
                          const string& object,
                          const string& action);


  ACLEntry(X509* cert);

  const string& GetAction() const;
  const string& GetObject() const;

 private:
  Principle* p;
  string object_;
  string action_;
};

class ACL {
  typedef hash_map<ActionSpecifier,bool,hash<ActionSpecifier> > AclHashMap;

 public:
  ACL(Principle* principle);

  void SetAccess(const ActionSpecifier& action, bool granted);
  bool IsAccessGranted(const ActionSpecifier& action);

  bool SerializeToACLList(::google::protobuf::RepeatedPtrField<proto::ACLEntry>* acls);

 private:
  Principle* principle_;
  AclHashMap acl_;
};

} // namespace larpc

#endif // _ACL_H

