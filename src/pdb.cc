/**
 * pdb.cc - Principle DB
 * Copyright (C) 2011 Andrew Reusch <areusch@gmail.com>
 *
 */

#include "pdb.h"
#include <utility>
#include <boost/foreach.hpp>

namespace larpc {

using ::std::pair;
using ::std::make_pair;

PrincipleDatabase::PrincipleDatabase(LaRPCFactory* factory) :
    factory_(factory), next_available_id_(1) {}

PrincipleDatabase::~PrincipleDatabase() {
  for (hash_map<id_t, Principle*>::iterator it = principles_by_id_.begin();
       it != principles_by_id_.end();
       it++) {
    delete (*it).second;
  }
}

Principle* PrincipleDatabase::Add(Principle* p) {
  if (!p)
    return NULL;

  if (Get(p).first)
    return false;

  Principle* pdb_principle = p->Clone();
  AssignNextAvailableId(pdb_principle);
  principles_by_id_[pdb_principle->GetId()] = pdb_principle;
}

pair<Principle*,id_t> PrincipleDatabase::Get(Principle* p) const {
  return Get(p->GetPublicKey());
}

pair<Principle*,id_t> PrincipleDatabase::Get(EVP_PKEY* p) const {
  PrincipleIdMap::const_iterator existing_principle_id = principles_by_public_key_.find(p);

  if (existing_principle_id == principles_by_public_key_.end()) {
    return make_pair<Principle*,Principle::id_t>(NULL, 0);
  }

  hash_map<Principle::id_t,Principle*>::const_iterator existing_principle =
    principles_by_id_.find((*existing_principle_id).second);

  return make_pair<Principle*,Principle::id_t>((*existing_principle).second,
                                               (*existing_principle).first);
}

bool PrincipleDatabase::IsLocal(Principle* p) {
  pair<Principle*, id_t> result = Get(p->GetPublicKey());
  if (!result.first)
    return false;

  return result.first->HasPrivateKey();
}

bool PrincipleDatabase::Remove(Principle* p) {
  if (principles_by_public_key_.find(p->GetPublicKey()) != principles_by_public_key_.end())
    principles_by_id_.erase(principles_by_public_key_[p->GetPublicKey()]);

  return principles_by_public_key_.erase(p->GetPublicKey()) > 0;
}

void PrincipleDatabase::AssignNextAvailableId(Principle* p) {
  p->SetId(next_available_id_++);
  principles_by_public_key_.insert(make_pair<EVP_PKEY*, id_t>(p->GetPublicKey(), p->GetId()));
}

PrincipleDatabase::const_iterator PrincipleDatabase::begin() const {
  return principles_by_id_.begin();
}

PrincipleDatabase::const_iterator PrincipleDatabase::end() const {
  return principles_by_id_.end();
}

bool PrincipleDatabase::Serialize(ZeroCopyOutputStream* out, CryptoInterface* crypto) {
  typedef pair<id_t, Principle*> hash_map_iterator;
  BOOST_FOREACH(hash_map_iterator it, principles_by_id_) {
    proto::PrincipleDescriptor desc;
    it.second->MergePublicPrivateData(&desc, crypto);

    if (!desc.SerializeToZeroCopyStream(out))
      return false;
  }

  return true;
}

} // namespace larpc
