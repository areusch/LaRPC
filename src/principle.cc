/**
 * principle.cc - LaRPC principle.
 * Copyright (C) 2010 Andrew Reusch <areusch@gmail.com>
 *
 */

#include "principle.h"
#include <sstream>
#include <boost/lexical_cast.hpp>
#include <glog/logging.h>
#include <openssl/crypto.h>
#include "acl.h"
#include "crypto.h"
#include "larpc.h"

namespace larpc {

using ::boost::lexical_cast;
using ::std::pair;
using ::std::stringstream;

Principle* Principle::FromDescriptor(PrincipleDatabase* pdb,
                                     const proto::PrincipleDescriptor& descriptor) {
  if (!descriptor.IsInitialized())
    return NULL;

  EVP_PKEY* public_key = EVP_PKEY_new();
  if (!CryptoInterface::PublicKeyFromPKCS8String(descriptor.public_key(),
                                                 &public_key)) {
    LOG(ERROR) << "Cannot deserialize principle public key!";
    return NULL;
  }

  Principle* existing_principle = pdb->Get(public_key).first;

  if (existing_principle) {
    EVP_PKEY_free(public_key);
    return existing_principle;
  }

  return new Principle(public_key, descriptor.display_name());
}

Principle::Principle(EVP_PKEY* public_key, const string& name) :
    public_key_(public_key), private_key_(NULL), acl_(NULL),
    version_(0), id_(-1), name_(name) {
  CRYPTO_add(&public_key_->references, 1, CRYPTO_LOCK_EVP_PKEY);
}


Principle::Principle(X509* cert,
                     EVP_PKEY* public_key,
                     EVP_PKEY* private_key,
                     unsigned int id,
                     const string& name) :
    public_key_(public_key), private_key_(private_key),
    acl_(NULL), trusting_cert_(cert), version_(0), id_(id), name_(name) {

  if (public_key_ == NULL) {
    public_key_ = X509_PUBKEY_get(X509_get_X509_PUBKEY(cert));
  } else {
    CHECK(X509_PUBKEY_get(X509_get_X509_PUBKEY(cert)) == public_key);
  };

  CRYPTO_add(&public_key_->references, 1, CRYPTO_LOCK_EVP_PKEY);
  CRYPTO_add(&private_key_->references, 1, CRYPTO_LOCK_EVP_PKEY);
}

Principle::~Principle() {
  if (public_key_)
    EVP_PKEY_free(public_key_);

  if (private_key_)
    EVP_PKEY_free(private_key_);

  if (trusting_cert_)
    X509_free(trusting_cert_);
}

Principle* Principle::Clone() {
  Principle* clone = new Principle(trusting_cert_, public_key_, private_key_, id_, name_);
  clone->version_ = version_;

  return clone;
}

const ACL* Principle::GetAcl() const {
  return acl_;
}

string Principle::GetName() const {
  return name_;
}

EVP_PKEY* Principle::GetPublicKey() const {
  return public_key_;
}

unsigned int Principle::GetId() const {
  return id_;
}

bool Principle::IsOwnedByPDB() const {
  return id_ != -1;
}

void Principle::SetAcl(ACL* acl) {
  acl_ = acl;
}

bool Principle::DecryptPrivateKey() {
  return false;
}

bool Principle::IsPrivateKeyDecrypted() const {
  return true;
}

bool Principle::HasPrivateKey() const {
  return private_key_ != NULL;
}

void Principle::SetId(unsigned int id) {
  id_ = id;
}

void Principle::MergePublicData(proto::PrincipleDescriptor* out) const {
  out->set_display_name(name_);
  CHECK(CryptoInterface::PublicKeyToPKCS8String(public_key_,
                                                out->mutable_public_key())) <<
    "Unexpectedly cannot serialize public key!";
  out->set_version(version_);

  if (acl_) {
    CHECK(acl_->SerializeToACLList(out->mutable_acls()));
  }
}

void Principle::MergePublicPrivateData(proto::PrincipleDescriptor* out,
                                       CryptoInterface* crypto) const {
  CHECK(private_key_ != NULL)
    << "Tried to merge public/private data with NULL private data!";

  MergePublicData(out);
  CHECK(crypto->PrivateKeyToPKCS8String(private_key_,
                                        out->add_encrypted_private_key())) <<
    "Unexpectedly cannot serialize private key!";
}


bool Principle::operator <(const Principle& other) const {
  return other.id_ < id_;
}

bool Principle::operator==(const Principle& p) const {
  return eq_principle()(*this, p);
}

bool Principle::AddPrivateKey(EVP_PKEY* private_key) {
  if (private_key_ || !private_key)
    return false;

  private_key_ = private_key;

  return true;
}

// X509_NAME encoding:
//  - PK = base64-encoded public key
//  - DN = Display Name
//  - V = Version
//
// Receiving nodes should be able to verify that the display name was valid
// at some point in the past by constructing an appropriate principle, hashing
// the public parts, and verifying the hash against its version history.
bool Principle::FillX509Name(CryptoInterface* crypto, X509_NAME* out_name) {
  map<string,string> out_map;

  string encoded_pubkey;
  if (!crypto->PublicKeyToPKCS8String(public_key_, &encoded_pubkey))
    return false;

  out_map["PK"] = encoded_pubkey;
  out_map["DN"] = name_;
  stringstream version_converter;
  version_converter << version_;
  CHECK(!version_converter.fail()) << "Cannot encode principle version";

  out_map["V"] = version_converter.str();
  X509Name name(out_map);
  return name.Fill(out_name);
}

Principle* Principle::FromX509Name(X509Name* name,
                                   PrincipleDatabase* pdb) {
  if (name->find("PK") == name->end() ||
      name->find("DN") == name->end() ||
      name->find("V") == name->end())
    return NULL;

  stringstream ss((*name)["V"]);
  uint32_t version;
  ss >> version;
  if (ss.fail())
    return NULL;

  EVP_PKEY* pubkey = NULL;
  if (!CryptoInterface::PublicKeyFromPKCS8String((*name)["PK"], &pubkey))
    return NULL;

  if (pdb) {
    // Try to find principle
    pair<Principle*, Principle::id_t> existing_principle = pdb->Get(pubkey);
    if (existing_principle.first) {
      EVP_PKEY_free(pubkey);
      return existing_principle.first;
    }
  }

  // Principle does not exist; construct it.
  auto_ptr<Principle> new_principle(new Principle(pubkey, (*name)["DN"]));
  new_principle->version_ = version;

  return new_principle.release();
}

// TODO migrate to pdb
/*
bool Principle::SignAdoptPrivateKey(CryptoInterface* crypto,
                                    EVP_PKEY* private_key,
                                    int expiry_time_days,
                                    map<string,string> machine_name,
                                    EVP_PKEY* machine_public_key) {
  map<string,string> issuer_name;
  issuer_name["CN"] = GetName();

  cert_ = crypto->CreateCertificate(machine_name,
                                    machine_public_key,
                                    expiry_time_days,
                                    issuer_name,
                                    GetPublicKey(),
                                    private_key);
  if (!cert_)
    return false;

  private_key_ = private_key;
  return true;
}
*/

} // namespace larpc
