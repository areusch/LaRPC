/**
 * identity.h - Types of identity
 * Copyright (C) 2011 Andrew Reusch <areusch@gmail.com>
 *
 */

#ifndef _SRC_IDENTITY_H
#define _SRC_IDENTITY_H

#include <string>
#include <openssl/x509.h>

namespace larpc {

using ::std::string;

class CryptoInterface;
class Identity;
class PrincipleDatabase;
class Principle;

typedef Identity*(*identity_create_fn)(const string&, PrincipleDatabase*);

class Identity {
 protected:
  Identity(const string& identity);
  virtual ~Identity();

  bool WriteIdentityType(string* out);

  uint32_t identity_id_;

 public:
  virtual bool ToString(string* out) const = 0;
  virtual bool IsValid(CryptoInterface* crypto) const = 0;
  virtual long Hash() const;

  static Identity* FromString(const string& str, PrincipleDatabase* pdb);

  virtual bool operator==(const Identity& other) const = 0;

  bool IsSameType(const Identity& other) const;
};

class RoleIdentity : public Identity {
 public:
  RoleIdentity(Principle* creator,
               const string& name,
               Principle* role_player,
               X509* authorizing_cert);
  virtual ~RoleIdentity();

  Principle* GetCreator() const;
  const string& GetName() const;

  virtual bool ToString(string* out) const;
  static Identity* FromString(const string& s,
                              PrincipleDatabase* pdb);

  virtual bool IsValid(CryptoInterface* crypto) const;

  virtual bool operator==(const Identity& other) const;
 protected:
  // Creator of this role
  Principle* creator_;

  // Unique name among all roles created by creator_.
  string name_;

  // Principle playing this role.
  Principle* role_player_;

  // Cert authorizing the role player to play this role.
  X509* authorizing_cert_;
};

class PrincipleIdentity : public Identity {
 public:
  PrincipleIdentity(Principle* principle);
  virtual ~PrincipleIdentity();

  virtual bool ToString(string* out) const;
  static Identity* FromString(const string& s,
                              PrincipleDatabase* pdb);

  virtual bool IsValid(CryptoInterface* crypto) const;

  virtual bool operator==(const Identity& other) const;
 private:
  Principle* p_;
};

} // namespace larpc

#endif // _SRC_IDENTITY_H


