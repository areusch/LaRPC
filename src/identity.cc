/**
 * identity.cc - Types of identity
 * Copyright (C) 2011 Andrew Reusch <areusch@gmail.com>
 *
 */

#include "identity.h"
#include <inttypes.h>
#include <map>
#include <memory>
#include <utility>
#include <boost/interprocess/detail/atomic.hpp>
#include "crypto.h"
#include "hash_map.h"
#include "principle.h"

#define IDENTITY_STRING_MAX_LEN_CHARS  20

namespace larpc {

using ::std::auto_ptr;
using ::std::make_pair;
using ::std::map;
using ::std::pair;

#define REGISTER_IDENTITY(cls)                                          \
  namespace {                                                           \
  identity::register_identity _register_ ## cls(#cls,  &cls::FromString); \
  }                                                                     \

namespace identity {

typedef std::map<string, pair<uint32_t, identity_create_fn> > IdentityMap;

static IdentityMap& get_map() {
  static IdentityMap identity_map;
  return identity_map;
}

static uint32_t get_next_identity_id() {
  static volatile uint32_t next_identity_id = 0;

  ::boost::interprocess::detail::atomic_inc32(&next_identity_id);
}

struct register_identity {
  register_identity(const string& name, identity_create_fn fn) {
    get_map().insert(make_pair(name,
                               make_pair<uint32_t, identity_create_fn>(get_next_identity_id(), fn)));
  }
};

} // namespace identity

Identity::Identity(const string& identity) {
  CHECK(identity::get_map().find(identity) != identity::get_map().end());
  identity_id_ = identity::get_map()[identity].first;
}

Identity::~Identity() {}

long Identity::Hash() const {
  string s;
  if (!ToString(&s))
    return 0;

  return hash<string>()(s);
}

Identity* Identity::FromString(const string& str, PrincipleDatabase* pdb) {
  int delimiter = 0;
  for (int i = 0; i < str.length(); ++i) {
    if (str[i] == ':') {
      delimiter = i;
      break;
    }
    if (i == IDENTITY_STRING_MAX_LEN_CHARS)
      return NULL;
  }

  string type_descriptor = str.substr(0, delimiter + 1);
  if (identity::get_map().find(type_descriptor) == identity::get_map().end())
    return NULL;

  return identity::get_map()[type_descriptor].second(str, pdb);
}

bool Identity::IsSameType(const Identity& other) const {
  return other.identity_id_ == identity_id_;
}

RoleIdentity::RoleIdentity(Principle* creator,
                           const string& name,
                           Principle* role_player,
                           X509* authorizing_cert) :
    Identity("RoleIdentity"), creator_(creator), name_(name),
    role_player_(role_player), authorizing_cert_(authorizing_cert) {}

RoleIdentity::~RoleIdentity() {}

Principle* RoleIdentity::GetCreator() const {
  return creator_;
}

const string& RoleIdentity::GetName() const {
  return name_;
}

bool RoleIdentity::IsValid(CryptoInterface* crypto) const {
  if (!creator_ || !name_.length() || !role_player_ || !authorizing_cert_)
    return false;

  X509Name subject(X509_get_subject_name(authorizing_cert_));
  auto_ptr<Principle> cert_role_player(Principle::FromX509Name(&subject, NULL));
  if (!cert_role_player.get())
    return false;

  return EVP_PKEY_cmp(X509_get_pubkey(authorizing_cert_),
                      creator_->GetPublicKey()) == 1 &&
    (*role_player_) == *cert_role_player;
}

bool RoleIdentity::ToString(string* out) const {
  string temp("RoleIdentity:");
  string data;
  if (!CryptoInterface::X509ToString(authorizing_cert_, &data))
    return false;

  *out = temp + data;
  return true;
}

Identity* RoleIdentity::FromString(const string& str, PrincipleDatabase* pdb) {
  string header("RoleIdentity:");

  if (str.size() <= header.size())
    return NULL;

  proto::Role id;
  if (!id.ParseFromString(str.substr(header.size())))
    return NULL;

  if (id.granting_x509_cert_size() != 1)
    return NULL;

  Principle* creator = Principle::FromDescriptor(pdb, id.creator());
  if (!creator)
    return NULL;

  X509* cert;
  if (!CryptoInterface::X509FromString(id.granting_x509_cert(0), &cert)) {
    if (!creator->IsOwnedByPDB())
      delete creator;
    return NULL;
  }

  X509Name subject(X509_get_subject_name(cert));
  if (subject.find("ROLE") == subject.end()) {
    if (!creator->IsOwnedByPDB())
      delete creator;
    return NULL;
  }

  Principle* role_player = Principle::FromX509Name(&subject, pdb);
  if (!role_player) {
    X509_free(cert);
    if (!creator->IsOwnedByPDB())
      delete creator;
    return NULL;
  }

  return new RoleIdentity(creator, subject["ROLE"], role_player, cert);
}

bool RoleIdentity::operator==(const Identity& other) const {
  if (!IsSameType(other))
    return false;

  const RoleIdentity& other_role = (const RoleIdentity&) other;
  return other_role.creator_ == creator_ &&
    other_role.name_ == name_ &&
    other_role.role_player_ == role_player_ &&
    X509_cmp(authorizing_cert_, other_role.authorizing_cert_) == 1;
}

PrincipleIdentity::PrincipleIdentity(Principle* p) :
    Identity("PrincipleIdentity"), p_(p) {}

PrincipleIdentity::~PrincipleIdentity() {
  if (!p_->IsOwnedByPDB())
    delete p_;
}

bool PrincipleIdentity::ToString(string* out) const {
  string temp("PrincipleIdentity:");
  proto::PrincipleDescriptor desc;
  p_->MergePublicData(&desc);

  *out = temp + desc.SerializeAsString();
  return true;
}

Identity* PrincipleIdentity::FromString(const string& s, PrincipleDatabase* pdb) {
  string header = "PrincipleIdentity:";

  if (s.size() < header.size())
    return false;

  proto::PrincipleDescriptor desc;
  if (!desc.ParseFromString(s.substr(header.size())))
    return false;

  Principle* p = Principle::FromDescriptor(pdb, desc);
  if (!p)
    return NULL;

  return new PrincipleIdentity(p);
}

bool PrincipleIdentity::IsValid(CryptoInterface* crypto) const {
  return p_ != NULL;
}

bool PrincipleIdentity::operator==(const Identity& other) const {
  if (!IsSameType(other))
    return false;

  return p_ == ((const PrincipleIdentity&) other).p_;
}

REGISTER_IDENTITY(RoleIdentity);
REGISTER_IDENTITY(PrincipleIdentity);

} // namespace larpc
