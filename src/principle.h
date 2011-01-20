/**
 * principle.h - LaRPC Prinicple encapsulation.
 * Copyright (C) 2010 Andrew Reusch <areusch@gmail.com>
 *
 */

#ifndef _PRINCIPLE_H
#define _PRINCIPLE_H

#include <string>
#include <glog/logging.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include "proto/larpc.pb.h"
#include "crypto.h"
#include "util.h"

namespace larpc {

using ::std::string;

class ACL;
class LaRPCFactory;

// All LaRPC priniciples have a public key and a set of machine keys that
// trust that principle. Most of the security model is concerned with keeping
// this view consistent.
class Principle {
 public:
  static Principle* FromDescriptor(LaRPCFactory* factory,
                                   const PrincipleDescriptor& descriptor);

  Principle(EVP_PKEY* public_key, const string& name);

  Principle(X509* cert, 
            EVP_PKEY* public_key, 
            EVP_PKEY* private_key, 
            unsigned int id, 
            const string& name);

  ACL* GetAcl();
  const ACL* GetAcl() const;
  string GetName() const; 
  X509* GetCert() const;
  EVP_PKEY* GetPublicKey() const;
  unsigned int GetId() const;
  bool HasPrivateKey() const;

  void SetAcl(ACL* acl);

  bool DecryptPrivateKey();

  bool operator<(const Principle& p) const;

  // Serialization functions
  // Serialize the public data fields encapsulated by this Principle. The list of fields is
  // maintained in larpc.proto.
  void MergePublicData(PrincipleDescriptor* out) const;

  // Serialize all fields stored in the PrincipleDescriptor. Use this function with care; never
  // transmit the result of this function to another node.
  void MergePublicPrivateData(PrincipleDescriptor* out, CryptoInterface* crypto) const;

  // Set the id. Never call this.
  void SetId(unsigned int id);

  bool SignAdoptPrivateKey(CryptoInterface* crypto, 
                           EVP_PKEY* private_key, 
                           int expiry_time_days,
                           map<string,string> machine_name,
                           EVP_PKEY* machine_public_key);
 private:
  X509* cert_;
  EVP_PKEY* public_key_;
  EVP_PKEY* private_key_;
  ACL* acl_;
  uint32_t version_;
  unsigned int id_;
  string name_;

  friend class LaRPCFactory;

  DISALLOW_EVIL_CONSTRUCTORS(Principle);
};

struct eq_principle {
  bool operator()(const Principle& a, const Principle& b) const {
    EVP_PKEY* a_pubkey = a.GetPublicKey();
    EVP_PKEY* b_pubkey = b.GetPublicKey();
    
    return EVP_PKEY_cmp(a_pubkey, b_pubkey) == 0;
  }
};

struct lt_principle {
  bool operator()(const Principle& a, const Principle& b) const {
    string a_pubkey;
    CHECK(CryptoInterface::PublicKeyToPKCS8String(a.GetPublicKey(), &a_pubkey));

    string b_pubkey;
    CHECK(CryptoInterface::PublicKeyToPKCS8String(a.GetPublicKey(), &a_pubkey));

    return a_pubkey < b_pubkey;
  }
};

struct lt_principle_ptr {
  bool operator()(Principle* const a, Principle* const b) const {
    lt_principle h;
    return h(*a, *b);
  }
};

} // namespace larpc

#endif // _PRINCIPLE_H
