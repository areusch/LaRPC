/**
 * pdb.h - Principles DB.
 * Copyright (C) 2011 Andrew Reusch <areusch@gmail.com>
 *
 */

#ifndef _SRC_PDB_H
#define _SRC_PDB_H

#include <map>
#include <string>
#include "hash_map.h"
#include <google/protobuf/io/zero_copy_stream.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include "principle.h"

HASHTABLE_NAMESPACE_START

template <>
struct hash<EVP_PKEY*> {
  int operator()(EVP_PKEY* const pubkey) const {
    int pubkey_size = i2d_PublicKey(pubkey, NULL);
    CHECK(pubkey_size > 0)
      << "Cannot compute hashed pubkey size for " << pubkey;

    unsigned char pubkey_hash[pubkey_size + 1];
    CHECK(i2d_PublicKey(pubkey, (unsigned char**) &pubkey_hash) == pubkey_size)
      << "Cannot hash public key " << pubkey;
    pubkey_hash[pubkey_size] = '\0';

    return hash<const char*>()((const char*) pubkey_hash);
  }
};

HASHTABLE_NAMESPACE_END

namespace larpc {

using ::google::protobuf::io::ZeroCopyInputStream;
using ::std::string;

class LaRPCFactory;

struct eq_evp_pkey {
  bool operator()(EVP_PKEY* const a, EVP_PKEY* const b) const {
    return EVP_PKEY_cmp(a, b) == 1;
  }
};

class PDBEntry {
 public:
  static PDBEntry* Create(EVP_PKEY* principle_key,
                          time_t expiration_time,
                          Principle* p,
                          LaRPCFactory* factory);

  static PDBEntry* FromX509(X509* x509);

  Principle* GetPrinciple() const;

 protected:
  PDBEntry();
  X509* cert_;
  Principle* p_;
};

class PrincipleDatabase {
 public:
  typedef hash_map<EVP_PKEY*, Principle::id_t, hash<EVP_PKEY*>, eq_evp_pkey> PrincipleIdMap;

  typedef hash_map<Principle::id_t, Principle*>::iterator iterator;
  typedef hash_map<Principle::id_t, Principle*>::const_iterator const_iterator;

  /**
   * Read serialized data stored in the given input stream and construct a
   * Principle DB as appropriate. Returns NULL if the input is corrupted.
   *
   * @param input Zero-copy input stream to read data from.
   */
  static PrincipleDatabase* FromInputStream(ZeroCopyInputStream* input);

  /**
   * Construct a new, empty PDB.
   */
  PrincipleDatabase(LaRPCFactory* factory);
  virtual ~PrincipleDatabase();

  /**
   * Add the given Principle to the local PDB. Returns true if the add
   * succeeds. If the add succeeds, the PDB now owns the pointer; else ownership
   * remains with the calling function.
   *
   * @param p Principle to add.
   * @return pointer to the internal copy of the principle, or NULL if
   *         adding the principle failed.
   */
  Principle* Add(Principle* p);

  /** Evaluate the public key contained in p and decides if an existing known
   * principle contains a matching public key. Returns a pair containing the
   * existing principle and its internal id (used for quicker identification),
   * or pair(NULL, 0) if no existing principle matched p.
   */
  std::pair<Principle*,id_t> Get(Principle* p) const;

  /** Evaluate p and decides if an existing known principle contains a
   * matching public key. Returns a pair containing the existing
   * principle and its internal id (used for quicker identification),
   * or pair(NULL, 0) if no existing principle matched p.
   */
  std::pair<Principle*,id_t> Get(EVP_PKEY* p) const;

  /** Retrieve the principle whose index is id. Returns NULL if no such
   * principle has an id of id.
   */
  Principle* Get(id_t id) const;

  /**
   * Determine if p is a local principle, where p is any valid Principle object
   * in memory (not necessarily a pointer internal to the PDB.
   *
   * @param p Principle in question.
   * @return true if a principle matches p in the PDB and the matched principle
   *         is local.
   */
  bool IsLocal(Principle* p);

  /**
   * If p exists in the PDB, removes it.
   *
   * @param p Principle to remove.
   * @return true if a change was made to the PDB.
   */
  bool Remove(Principle* p);

  const_iterator begin() const;
  const_iterator end() const;

  /**
   * Adopt the given principle as a local principle; stores the given private
   * key as the principle's private key. This assignment expires after the
   * given expiration time.
   */
  bool AdoptAsLocal(Principle* p,
                    EVP_PKEY* private_key,
                    int expiry_time_days);
 private:
  /**
   * Determine the next free principle ID and call p->SetId passing
   * the next availble ID.
   *
   * @param p Principle to assign an id.
   */
  void AssignNextAvailableId(Principle* p);

  LaRPCFactory* factory_;

  // Note: the values in this map point to Principle objects that the PDB _OWNS_.
  // delete them when you erase from this map.
  hash_map<id_t, Principle*> principles_by_id_;
  PrincipleIdMap principles_by_public_key_;
  Principle::id_t next_available_id_;
};

} // namespace larpc


#endif // _SRC_PDB_H


