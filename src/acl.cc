/**
 * acl.cc - Desc
 * Copyright (C) 2010 Andrew Reusch <areusch@gmail.com>
 *
 */

#include "acl.h"

namespace larpc {

bool ActionSpecifier::operator==(const ActionSpecifier& other) const {
  return principle_ == other.principle_ &&
    object_ == other.object_ &&
    action_ == other.action_;
}

ACL::ACL(Principle* principle) : principle_(principle) {}

void ACL::SetAccess(const ActionSpecifier& action, bool granted) {
  acl_[action] = granted;
}

bool ACL::IsAccessGranted(const ActionSpecifier& action) {
  AclHashMap::iterator it = acl_.find(action);
  if (it == acl_.end())
    return false;

  return (*it).second;
}

bool ACL::SerializeToACLList(::google::protobuf::RepeatedPtrField<proto::ACLEntry>* acls) {
  return true;
}

} // namespace larpc
