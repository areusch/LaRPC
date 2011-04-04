/**
 * multiplexer.cc - LaRPC Socket Multiplexer.
 * Copyright (C) 2010 Andrew Reusch <areusch@gmail.com>
 *
 */

#include "multiplexer.h"
#include <inttypes.h>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/foreach.hpp>
#include <boost/interprocess/sync/scoped_lock.hpp>
#include <boost/lambda/lambda.hpp>
#include <boost/thread/locks.hpp>
#include "proto/larpc.pb.h"
#include "larpc.h"
#include "util.h"

namespace larpc {

using ::boost::bind;
using ::boost::cref;
using ::boost::ref;
using ::boost::lambda::var;
using ::boost::asio::async_read;
using ::boost::asio::buffer;
using ::boost::asio::io_service;
using ::boost::asio::detail::socket_ops::host_to_network_long;
using ::boost::asio::detail::socket_ops::network_to_host_long;
using ::boost::interprocess::scoped_lock;
using ::boost::unique_lock;

uint64_t GetCPUId() {
  int cpuid = 3; // return processor serial number.

  asm ( "mov %1, %%eax; "
        "cpuid;"
        "mov %%eax, %0;"
        :"=r"(cpuid) /* output */
        :"r"(cpuid) /* input */
        :"%eax" /* clobbered register */
    );

  return cpuid;
}

bool eq_channel_ptr::operator()(Channel* const a, Channel* const b) const {
  return a->GetChannelId() == b->GetChannelId();
}

typedef boost::function2<bool, const error_code&, ::std::size_t> completion_function;
typedef boost::function2<void, const error_code&, ::std::size_t> handler_function;

Multiplexer::Multiplexer(Socket* socket) :
    disallow_new_channels_(false),
    socket_(socket),
    ostream_(::boost::bind(&Socket::Write, socket_, _1, _2)),
    is_shut_down_(false), is_shutting_down_(false) {}

void Multiplexer::SendChannelSetup() {
  proto::ChannelSetup msg;

  if (factory_->GetConfig().advertise_principles()) {
    scoped_lock<mutex> lock_(factory_->state_lock_);

    typedef pair<Principle::id_t, const Principle*> PDBIterator;
    BOOST_FOREACH(PDBIterator principle, (*(const PrincipleDatabase*) factory_->pdb_.get())) {
      if (principle.second->HasPrivateKey())
        principle.second->MergePublicData(msg.add_principles());
    }
  }

  CHECK(!factory_->crypto_.PublicKeyToPKCS8String(
          factory_->machine_key_,
          msg.mutable_machine_public_key()))
    << "Unexpectedly cannot serialize machine public key :(";

  SendMessage(msg.SerializeAsString());
  StartReceiveLoop();
}

void Multiplexer::SendMessage(const string& msg) {
  uint64_t msg_size_network_order = host_to_network_long(msg.size());
  ostream_.write(string((char*) &msg_size_network_order, sizeof(msg_size_network_order)));
  ostream_.write(msg);
}

void Multiplexer::StartReceiveLoop() {
  int* message_length = new int;

  socket_->Read(buffer(message_length, sizeof(message_length)),
                bind(&Multiplexer::MessageLengthReceived,
                     this,
                     message_length,
                     boost::asio::placeholders::error));
}

void Multiplexer::MessageLengthReceived(int* message_length,
                                        const error_code& error) {
  if (!error) {
    *message_length = network_to_host_long(*message_length);
    uint8_t* message_buffer = new uint8_t[*message_length];

    socket_->Read(buffer(message_buffer, *message_length),
                  bind(&Multiplexer::MessageReceived,
                       this,
                       message_length,
                       message_buffer,
                       boost::asio::placeholders::error));
  } else {
    delete message_length;
    HandleErrorCondition(error);
  }
}

void Multiplexer::MessageReceived(int* message_length,
                                  uint8_t* message_buffer,
                                  const error_code& error) {
  if (!error) {
    ProcessOneMessage(string((const char*) message_buffer, (size_t) *message_length));
  }

  delete message_length;
  delete message_buffer;

  if (error) {
    HandleErrorCondition(error);
  }
}

void Multiplexer::ProcessOneMessage(const string& message) {
  proto::MultiplexerMessage msg;
  if (!msg.ParseFromString(message)) {
    LOG(ERROR) << "Cannot parse multiplexer message on " << Describe()
               << "; closing connection!";
    AsyncShutdown();
  }
}

void Multiplexer::HandleErrorCondition(const error_code& error) {
  // TODO(andrew): better error handling
  if (error)
    AsyncShutdown();
}

string Multiplexer::Describe() {
  string status;
  if (socket_->IsOpen())
    status = "Open";
  else
    status = "Closed";

  return status +
    " multiplexer to " +
    util::BoostEndpointToString(socket_->GetRemoteEndpoint()) +
    " bound on " +
    util::BoostEndpointToString(socket_->GetLocalEndpoint());
}

void Multiplexer::Shutdown() {
  AsyncShutdown();

  unique_lock<mutex> lock(shutdown_lock_);
  while (!IsShutdown())
    shutdown_wait_.wait(lock);
}

void Multiplexer::AsyncShutdown() {
  {
    scoped_lock<mutex> lock(shutdown_lock_);

    if (is_shutting_down_)
      return;

    is_shutting_down_ = true;
  }

  AsyncShutdownOnce();
}

void Multiplexer::AsyncShutdownOnce() {
  {
    scoped_lock<mutex> lock(channel_lock_);

    proto::ChannelControl control;
    typedef std::pair<const string,Channel*> iter;
    BOOST_FOREACH(iter ch, channels_) {
      ch.second->Shutdown(false);
      control.add_close_channel_id(ch.second->GetChannelId());
    }

    SendMessage(control.SerializeAsString());

    // TODO(andrew): How do we delete channels?

    is_shut_down_ = true;
    shutdown_wait_.notify_all();
  }
}

} // namespace larpc
