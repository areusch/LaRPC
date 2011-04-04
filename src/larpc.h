/**
 * larpc.h - LaRPC main interface class.
 * Copyright (C) 2010 Andrew Reusch <areusch@gmail.com>
 *
 */

#ifndef _LARPC_H
#define _LARPC_H

#include <iostream>
#include <map>
#include <memory>
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
#include "pdb.h"
#include "principle.h"


namespace larpc {

using ::boost::asio::ip::tcp;
using ::boost::asio::io_service;
using ::boost::function0;
using ::boost::mutex;
using ::std::auto_ptr;
using ::std::istream;
using ::std::multimap;
using ::std::ostream;
using ::std::string;

typedef function0<char*> key_generator_func;

class LaRPCFactory {
 private:
  typedef multimap<const Principle*,Channel*> PrincipleChannelMap;
 public:
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
  bool MergeConfig(const proto::Config& config);

  /** Returns a read-only copy of this node's configuration.
   */
  const proto::Config& GetConfig();

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

  // --------------------------[ Principle Methods ]----------------------------
  //
  // These functions deal with access to principles. Do not call these functions
  // outside the event loop; locking is not provided.

  // Query the Principle DB for the given principle.
  inline Principle* GetPrinciple(Principle::id_t id) {
    return pdb_->Get(id);
  }

  inline Principle* GetPrinciple(EVP_PKEY* public_key) {
    return pdb_->Get(public_key).first;
  }

  // Ensures that a principle object is present for each principle listed
  // in the LaRPC configuration. Closes any channels whose local client no
  // longer exists.
  // Expects state_lock_ to be locked.
  //
  // principles may be NULL, in which case principles will be read from the
  // file given in the configuration.
  void ReplacePrinciples(set<Principle*>* principles);

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
  EVP_PKEY* ReadMachineKey(const proto::Config& config);

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

  bool LoadPrinciplesFromConfig(const proto::Config& config,
                                set<Principle*>* out_principles);

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

  // Total per-instance LaRPC library state. This tracks all Multiplexers and
  // Principles, both local and non-local. Changes to these data structures
  // requires holding state_lock_.
  mutex state_lock_;
  set<Multiplexer*> multiplexers_;
  PrincipleChannelMap channels_by_local_principle_;
  PrincipleChannelMap channels_by_remote_principle_;
  auto_ptr<PrincipleDatabase> pdb_;

  // Local machine key (private key should be present).
  EVP_PKEY* machine_key_;
  key_generator_func machine_key_gen_;

  // Machine key store for remote sides.
  KeyStore key_store_;

  // Configuration data structure.
  proto::Config config_;

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


