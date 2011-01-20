/**
 * principle.cc - LaRPC principle.
 * Copyright (C) 2010 Andrew Reusch <areusch@gmail.com>
 *
 */

#include "principle.h"
#include <glog/logging.h>
#include "crypto.h"
#include "larpc.h"

namespace larpc {

using ::std::pair;

Principle* Principle::FromDescriptor(LaRPCFactory* factory,
                                     const PrincipleDescriptor& descriptor) {
  if (!descriptor.IsInitialized())
    return NULL;

  EVP_PKEY* public_key;
  if (!CryptoInterface::PublicKeyFromPKCS8String(descriptor.public_key(), 
                                                 &public_key)) {
    LOG(ERROR) << "Cannot deserialize principle public key!";
    return NULL;
  }

  pair<Principle*, LaRPCFactory::id_t> existing_principle =
    factory->GetPrinciple(public_key);

  if (existing_principle.first != NULL) {
    EVP_PKEY_free(public_key);
    return existing_principle.first;
  }

  return new Principle(public_key, descriptor.display_name());
}

Principle::Principle(EVP_PKEY* public_key, const string& name) :
    cert_(NULL), public_key_(public_key), private_key_(NULL), acl_(NULL),
    version_(0), id_(-1), name_(name) {}
  

Principle::Principle(X509* cert, 
                     EVP_PKEY* public_key,
                     EVP_PKEY* private_key, 
                     unsigned int id, 
                     const string& name) :
    cert_(cert), public_key_(public_key), private_key_(private_key), 
    acl_(NULL), version_(0), id_(id), name_(name) {

  if (public_key_ == NULL) {
    public_key_ = X509_PUBKEY_get(X509_get_X509_PUBKEY(cert));
  } else {
    CHECK(X509_PUBKEY_get(X509_get_X509_PUBKEY(cert)) == public_key);
  };
}

const ACL* Principle::GetAcl() const {
  return acl_;
}

string Principle::GetName() const {
  return name_;
}

X509* Principle::GetCert() const {
  return cert_;
}

EVP_PKEY* Principle::GetPublicKey() const {
  return public_key_;
}

unsigned int Principle::GetId() const {
  return id_;
}

void Principle::SetAcl(ACL* acl) {
  acl_ = acl;
}

bool Principle::DecryptPrivateKey() {
  return false;
}

bool Principle::HasPrivateKey() const {
  return private_key_ != NULL;
}

void Principle::SetId(unsigned int id) {
  id_ = id;
}

void Principle::MergePublicData(PrincipleDescriptor* out) const {
  out->set_display_name(name_);
  CHECK(CryptoInterface::PublicKeyToPKCS8String(public_key_,
                                                out->mutable_public_key())) <<
    "Unexpectedly cannot serialize public key!";
  out->set_version(version_);

  if (cert_) {
    CHECK(CryptoInterface::X509ToString(cert_, out->add_trusting_x509_certificate()));
  }
}

void Principle::MergePublicPrivateData(PrincipleDescriptor* out, 
                                       CryptoInterface* crypto) const {
  CHECK(private_key_ != NULL) 
    << "Tried to merge public/private data with NULL private data!";

  MergePublicData(out);
  CHECK(crypto->PrivateKeyToPKCS8String(private_key_, 
                                        out->mutable_encrypted_private_key())) <<
    "Unexpectedly cannot serialize private key!";
}


bool Principle::operator <(const Principle& other) const {
  return other.id_ < id_;
}

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

} // namespace larpc
