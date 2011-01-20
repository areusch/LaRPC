/**
 * larpc.h - LaRPC main interface class.
 * Copyright (C) 2010 Andrew Reusch <areusch@gmail.com>
 *
 */

#ifndef _LARPC_H
#define _LARPC_H

#include <iostream>
#include <map>
#include <string>
#include <set>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/thread/mutex.hpp>
#include <glog/logging.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include "proto/larpc.pb.h"
#include "constants.h"
#include "hash_map.h"
#include "key.h"
#include "multiplexer.h"
#include "network.h"
#include "principle.h"

HASHTABLE_NAMESPACE_START

template <>
struct hash<EVP_PKEY*> {
  int operator()(EVP_PKEY* const pubkey) const {
    int pubkey_size = i2d_PublicKey(pubkey, NULL);
    CHECK(pubkey_size > 0)
      << "Cannot compute hashed pubkey size for " << pubkey;

    unsigned char pubkey_hash[pubkey_size + 1];
    CHECK(i2d_PublicKey(pubkey, (unsigned char**) &pubkey_hash) == 1)
      << "Cannot hash public key " << pubkey;
    pubkey_hash[pubkey_size] = '\0';

    return hash<const char*>()((const char*) pubkey_hash);
  }
};

HASHTABLE_NAMESPACE_END

namespace larpc {

struct eq_evp_pkey {
  bool operator()(EVP_PKEY* const a, EVP_PKEY* const b) const {
    return EVP_PKEY_cmp(a, b) == 1;
  }
};

using ::boost::asio::ip::tcp;
using ::boost::asio::io_service;
using ::boost::function0;
using ::boost::mutex;
using ::std::istream;
using ::std::multimap;
using ::std::ostream;
using ::std::string;

typedef function0<char*> key_generator_func;

class LaRPCFactory {
 private:
  typedef multimap<const Principle*,Channel*> PrincipleChannelMap;
 public:
  typedef unsigned int id_t;
  typedef hash_map<EVP_PKEY*, int, hash<EVP_PKEY*>, eq_evp_pkey> PrincipleIdMap;

  static LaRPCFactory* FromConfigFile(const string& filename,
                                      Network* net,
                                      key_generator_func machine_key_gen);

  /**
   * Initialize the LaRPC factory using the default configuration.
   * No principles are added, and the default SSL security settings
   * as specified in larpc.proto are chosen.
   */
  LaRPCFactory(Network* net,
               tcp::endpoint bind_endpoint,
               key_generator_func machine_key_gen);
  virtual ~LaRPCFactory();

  /** Reads the node configuration from the given istream. Bytes will be
   * consumed from config to process as Config data structure.
   */
  bool ReadConfigFromStream(istream* config);
  
  /** Merge configuration data from the given Config protocol buffer.
   */
  bool MergeConfig(const Config& config);

  /** Returns a read-only copy of this node's configuration.
   */
  const Config& GetConfig();

  /** Write this node's configuration to the given ostream.
   */
  bool WriteConfigToStream(const ostream& config);

  /** Returns the number of active multiplexers.
   */
  int NumActiveMultiplexers();

  /** Take ownership of the socket pointed to by s and begin control
   * communications on the socket. Returns a new Multiplexer that represents
   * the state of the new control channel running on the given socket.
   */
  Multiplexer* NewMultiplexer(Socket* s);

  /** Evaluate the public key contained in p and decides if an existing known
   * principle contains a matching public key. Returns a pair containing the
   * existing principle and its internal id (used for quicker identification),
   * or pair(NULL, 0) if no existing principle matched p.
   */
  std::pair<Principle*,id_t> GetPrinciple(Principle* p);

  /** Evaluate p and decides if an existing known principle contains a
   * matching public key. Returns a pair containing the existing
   * principle and its internal id (used for quicker identification),
   * or pair(NULL, 0) if no existing principle matched p.
   */
  std::pair<Principle*,id_t> GetPrinciple(EVP_PKEY* p);

  /** Retrieve the principle whose index is id. Returns NULL if no such
   * principle has an id of id.
   */
  Principle* GetPrinciple(id_t id);
  
  /** Calls machine_key_gen to generate a new machine key and stores it
   * in the file named by new_keyfile. Returns true on success and false on
   * failure.
   */
  bool GenerateMachineKey(const string& new_keyfile);

  /** Begin asynchronously accepting connections on the control port. This
   * function returns immediately. All further processing occurs in the 
   * same thread as provided by the Network layer.
   */
  void Accept();

  /** Shuts down all multiplexers and stops accepting connections on the
   * control port. Blocks until all multiplexers have stopped and the
   * control socket has closed.
   */
  void Shutdown();

 private:
  EVP_PKEY* ReadMachineKey(const Config& config);

  // Decrypt the machine key stored in encrypted_machine_key;
  // may block if it needs to read a password from stdin.
  // Returns true on success, false on failure.
  bool DecryptMachineKey(char* encrypted_machine_key,
                         size_t encrypted_key_size_bytes,
                         char** decrypted_machine_key,
                         size_t* decrypted_key_size_bytes);

  // If a machine key is allocated/decrypted, free it.
  void MaybeFreeMachineKey();

  void ShutdownUnderLock_();

  bool LoadPrinciplesFromConfig(const Config& config, 
                                set<Principle*>* out_principles);

  // Ensures that a principle object is present for each principle listed
  // in the LaRPC configuration. Closes any channels whose local client no
  // longer exists.
  // Expects state_lock_ to be locked.
  void ReplacePrinciples();
  
  // Removes a principle and closes any open channels associated with it.
  // Expects a reference to a principle that exists inside of principles_.
  void RemovePrinciple(Principle* p);

  // Decide if p is not yet known to this instance of LaRPC. If so, it adds
  // p to the appropriate maps and notifies any interested parties.
  // Returns a pointer to the internal copy of the principle. Any further
  // operations regarding the principle should use this pointer.
  Principle* HandleNewPrinciple(Principle* p, bool is_local = false);

  // Add 
  void HandleNewLocalPrinciple(Principle* principle_in_map);

  void HandleAccept(Socket* s, const ::boost::system::error_code& error);

  void AssignNextAvailablePrincipleId(Principle* p);

  bool AdoptLocalPrinciple(Principle* p, EVP_PKEY* private_key);

  // Total per-instance LaRPC library state. This tracks all Multiplexers and
  // Principles, both local and non-local. Changes to these data structures
  // requires holding state_lock_.
  mutex state_lock_;
  set<Multiplexer*> multiplexers_;
  hash_map<int, Principle*> principles_;
  set<Principle*> local_principles_;
  PrincipleChannelMap channels_by_local_principle_;
  PrincipleChannelMap channels_by_remote_principle_;

  PrincipleIdMap principle_id_map_;
  id_t next_available_id_;

  // Local machine key (private key should be present).
  EVP_PKEY* machine_key_;
  key_generator_func machine_key_gen_;

  // Machine key store for remote sides.
  KeyStore key_store_;

  // Configuration data structure.
  Config config_;

  // ASIO layer; contains the connection-acceptor and IO service.
  tcp::endpoint listen_endpoint_;
  ServerSocket* conn_acceptor_;
  Network* net_;

  // Cryptography services, linked to our secure time layer
  CryptoInterface crypto_;

  friend class Multiplexer;
};

} // namespace larpc

#endif // _LARPC_H


