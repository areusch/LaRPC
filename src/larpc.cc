/**
 * larpc.cc - LaRPC Factory code.
 * Copyright (C) 2010 Andrew Reusch <areusch@gmail.com>
 *
 */

#include "larpc.h"
#include <fstream>
#include <iostream>
#include <memory>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/filesystem.hpp>
#include <boost/thread/locks.hpp>
#include <boost/thread/mutex.hpp>
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <openssl/dsa.h>
#include <openssl/evp.h>
#include "channel.h"
#include "crypto.h"
#include "key.h"
#include "util.h"

namespace larpc {

using ::boost::lock_guard;
using ::boost::mutex;
using ::boost::asio::ip::tcp;
using ::boost::filesystem::exists;
using ::boost::filesystem::file_size;
using ::google::protobuf::io::FileInputStream;
using ::google::protobuf::io::IstreamInputStream;
using ::std::auto_ptr;
using ::std::ios_base;
using ::std::fstream;
using ::std::make_pair;
using ::std::pair;
using util::BoostEndpointToString;

LaRPCFactory* LaRPCFactory::FromConfigFile(const string& filename,
                                           Network* network,
                                           key_generator_func machine_key_gen) {
  auto_ptr<LaRPCFactory> factory(
    new LaRPCFactory(network, tcp::endpoint(), machine_key_gen));

  if (!exists(filename)) {
    LOG(ERROR) << "Config file not found!";
    return NULL;
  }

  fstream config_file(filename.c_str(), ios_base::in);
  if (config_file.fail()) {
    LOG(ERROR) << "Cannot open config file for reading!";
    return false;
  }

  if (!factory->ReadConfigFromStream(&config_file)) {
    return NULL;
  }

  return factory.release();
}

static time_t gettime_unix() {
  return time(NULL);
}

LaRPCFactory::LaRPCFactory(Network* net,
                           tcp::endpoint endpoint,
                           key_generator_func machine_key_gen) :
    machine_key_gen_(machine_key_gen), net_(net),
    listen_endpoint_(endpoint), conn_acceptor_(NULL), crypto_(0, gettime_unix) {}

LaRPCFactory::~LaRPCFactory() {
  lock_guard<mutex> lock(state_lock_);

  MaybeFreeMachineKey();

  ShutdownUnderLock_();
}

void LaRPCFactory::MaybeFreeMachineKey() {
  if (machine_key_)
    EVP_PKEY_free(machine_key_);
}

bool LaRPCFactory::ReadConfigFromStream(istream* config) {
  IstreamInputStream input_stream(config);

  proto::Config cfg;
  if (!cfg.ParseFromZeroCopyStream(&input_stream)) {
    return false;
  }

  lock_guard<mutex> lock(state_lock_);
  Shutdown();
  config_.Clear();
  MaybeFreeMachineKey();


  return MergeConfig(cfg);
}

bool LaRPCFactory::MergeConfig(const proto::Config& config) {
  EVP_PKEY* new_machine_key = NULL;
  if (config_.machine_key_file() != config.machine_key_file()) {
    new_machine_key = ReadMachineKey(config);

    if (!new_machine_key)
      return false;
  }

  {
    lock_guard<mutex> lock(state_lock_);
    config_.MergeFrom(config);

    if (new_machine_key) {
      MaybeFreeMachineKey();
      machine_key_ = new_machine_key;
    }

    ReplacePrinciples(NULL);
  }

  return true;
}

EVP_PKEY* LaRPCFactory::ReadMachineKey(const proto::Config& config) {
  if (!exists(config.machine_key_file())) {
    LOG(ERROR) << "While parsing config: machine key doesn't exist!";
    return NULL;
  }

  size_t raw_machine_key_size_bytes = file_size(config_.machine_key_file());
  if (raw_machine_key_size_bytes > LARPC_PRIVATE_KEY_MAX_SIZE_BYTES) {
    LOG(ERROR) << "While parsing config: machine key "
               << config.machine_key_file()
               << " is too big (larger than "
               << LARPC_PRIVATE_KEY_MAX_SIZE_BYTES
               << ")!";
    return NULL;
  }

  proto::MachineKey key;
  {
    int fd = open(config.machine_key_file().c_str(), O_RDONLY);
    if (!fd) {
      LOG(ERROR) << "Could not open machine key file for reading!";
      return NULL;
    }

    FileInputStream fis(fd);
    if (!key.ParseFromZeroCopyStream(&fis)) {
      LOG(ERROR) << "Could not read machine key file!";
      return NULL;
    }
  }

  EVP_PKEY* machine_key = NULL;
  if (!CryptoInterface::PublicKeyFromPKCS8String(key.public_key(),
                                                 &machine_key)) {
    LOG(ERROR) << "Could not deserialize machine's public key!";
    return NULL;
  }

  if (!crypto_.PrivateKeyFromPKCS8String(key.private_key(),
                                         &machine_key)) {
    LOG(ERROR) << "Could not deserialize machine's private key!";
    EVP_PKEY_free(machine_key);
    return NULL;
  }

  // TODO: verify keys!
  return machine_key;
}

bool LaRPCFactory::DecryptMachineKey(char* encrypted_machine_key,
                                     size_t encrypted_key_size_bytes,
                                     char** decrypted_machine_key,
                                     size_t* decrypted_key_size_bytes) {
  if (!crypto_.DecryptBuffer((unsigned char*) encrypted_machine_key,
                             encrypted_key_size_bytes,
                             config_.machine_key_encryption(),
                             &key_store_,
                             (unsigned char**) decrypted_machine_key,
                             decrypted_key_size_bytes)) {
    LOG(ERROR) << "Cannot decrypt machine key!";
    return false;
  }
}

const proto::Config& LaRPCFactory::GetConfig() {
  return config_;
}

Multiplexer* LaRPCFactory::NewMultiplexer(Socket* s) {
  auto_ptr<Multiplexer> mux( new Multiplexer(s) );
  mux->SendChannelSetup();

  {
    lock_guard<mutex> lock(state_lock_);
    multiplexers_.insert(mux.get());
  }
  return mux.release();
}

bool LaRPCFactory::LoadPrinciplesFromConfig(const proto::Config& config,
                                            set<Principle*>* new_principles) {
  CHECK(new_principles != NULL) << "Cannot load principles into a NULL set.";

  if (!exists(config.local_principles_file())) {
    LOG(ERROR) << "Local Principle Store does not exist!";
    return false;
  }

  int local_principles_fd = open(config.local_principles_file().c_str(), O_RDONLY);
  if (local_principles_fd <= 0) {
    LOG(ERROR) << "Cannot open Local Principle Store at "
               << config.local_principles_file();
    return false;
  }

  FileInputStream principle_stream(local_principles_fd);

  proto::PrincipleDescriptor p;
  int num_failed_parses = 0;
  while (p.ParseFromZeroCopyStream(&principle_stream)) {
    auto_ptr<Principle> principle(Principle::FromDescriptor(this, p));
    if (principle.get()) {
      new_principles->insert(principle.release());
    } else {
      num_failed_parses++;
    }
  }

  if (num_failed_parses) {
    LOG(ERROR) << "While deserializing principle store in "
               << config.local_principles_file()
               << ": " << num_failed_parses << " principles could not be "
               << "deserialized.";
  }

  principle_stream.Close();
  close(local_principles_fd);

  return (new_principles->size() > 0);
}

void LaRPCFactory::ReplacePrinciples(set<Principle*>* principles) {
  // ASSERT locked?

  auto_ptr<set<Principle*> > config_principles;

  if (!principles) {
    config_principles.reset(new set<Principle*>);

    if (!LoadPrinciplesFromConfig(config_, config_principles.get())) {
      LOG(FATAL) << "Loaded a configuration that contained an unloadable "
                 << "principles file.";
      return;
    }

    principles = config_principles.get();
  }

  // Remove all local principles not present in the new configuration.
  // Merges in non-local principles.
  for (PrincipleDatabase::const_iterator it = pdb_->begin();
       it != pdb_->end();
       it++) {
    // YAY SLOW!
    for (set<Principle*>::iterator j = principles->begin();
         j != principles->end();
         j++) {
      if (**j == *((*it).second)) {
        if (pdb_->IsLocal(*j))
          RemovePrinciple((*it).second);
        break;
      }
    }
  }

  // Call HandleNewPrinciple() for any new principles loaded.
  for (set<Principle*>::iterator it = principles->begin();
       it != principles->end();
       it++) {
    if (!pdb_->Get(*it).first) {
      // New principle loaded
      CHECK(HandleNewPrinciple((*it), true));
    }
  }
}

void LaRPCFactory::RemovePrinciple(Principle* p) {
  // ASSERT locked?

  // Delete any channels with the principle at a local endpoint
  {
    pair<PrincipleChannelMap::iterator,PrincipleChannelMap::iterator>
      channels_ = channels_by_local_principle_.equal_range(p);

    if (channels_.first != channels_.second) {
      // Some channels exist that we need to delete
      for (PrincipleChannelMap::iterator it = channels_.first;
           it != channels_.second;
           ) {
        (*(it++)).second->Shutdown();
      }
    }
  }

  // Delete any channels with the principle at a remote endpoint
  {
    pair<PrincipleChannelMap::iterator,PrincipleChannelMap::iterator>
      channels_ = channels_by_remote_principle_.equal_range(p);

    if (channels_.first != channels_.second) {
      // Some channels exist that we need to delete
      for (PrincipleChannelMap::iterator it = channels_.first;
           it != channels_.second;
           ) {
        (*(it++)).second->Shutdown();
      }
    }
  }

  pdb_->Remove(p);
}

Principle* LaRPCFactory::HandleNewPrinciple(Principle* p, bool is_local) {
  // is_local should match p->HasPrivateKey()
  if (!(is_local ^ !p->HasPrivateKey()))
    return false;

  lock_guard<mutex> lock(state_lock_);
  pair<Principle*,id_t> existing_principle = pdb_->Get(p);

  if (existing_principle.first != NULL) {
    // Principle already known; examine change in is_local...

    if (is_local &&
        pdb_->IsLocal(existing_principle.first))
      HandleNewLocalPrinciple(existing_principle.first);

    return existing_principle.first;
  }

  // Principle not known, add it to PDB.
  Principle* internal_principle = pdb_->Add(p);
  if (!internal_principle)
    return NULL;

  if (is_local)
    HandleNewLocalPrinciple(p);

  return internal_principle;
}

void LaRPCFactory::HandleNewLocalPrinciple(Principle* principle_in_map) {


  // TODO: notify multiplexers...
}

void LaRPCFactory::Accept() {
  if (!conn_acceptor_) {
    conn_acceptor_ = net_->Listen(listen_endpoint_);
    if (!conn_acceptor_) {
      LOG(ERROR) << "LaRPC Factory: Cannot listen for connections!";
      return;
    }
  }

  conn_acceptor_->Accept(::boost::bind(&LaRPCFactory::HandleAccept, this, _1, _2));
}

void LaRPCFactory::HandleAccept(Socket* s, const ::boost::system::error_code& error) {
  if (!error) {
    lock_guard<mutex> lock(state_lock_);
    Multiplexer* mux = new Multiplexer(s);
    multiplexers_.insert(mux);
    mux->SendChannelSetup();
    mux->StartReceiveLoop();
  } else {
    LOG(ERROR) << "Failed to accept a TCP connection: " << error;
    delete s;
  }

  Accept();
}

void LaRPCFactory::Shutdown() {
  lock_guard<mutex> lock(state_lock_);

  ShutdownUnderLock_();
}

void LaRPCFactory::ShutdownUnderLock_() {
  set<Multiplexer*>::iterator it = multiplexers_.begin();
  while (it != multiplexers_.end()) {
    (*it++)->Shutdown();
  }
}

} // namespace larpc
