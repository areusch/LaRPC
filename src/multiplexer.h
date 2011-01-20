/**
 * multiplexer.h - LaRPC socket multiplexer.
 * Copyright (C) 2010 Andrew Reusch <areusch@gmail.com>
 *
 */

#ifndef _MULTIPLEXER_H
#define _MULTIPLEXER_H

#include <map>
#include <set>
#include <string>
#include <boost/asio.hpp>
#include <boost/function.hpp>
#include <boost/thread/condition_variable.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/once.hpp>
#include <openssl/evp.h>
#include "async_iostream.h"
#include "channel.h"
#include "hash_map.h"
#include "network.h"

namespace larpc {

using ::boost::asio::ip::tcp;
using ::boost::asio::io_service;
using ::boost::condition_variable;
using ::boost::function1;
using ::boost::once_flag;
using ::boost::system::error_code;
using ::std::map;
using ::std::set;
using ::std::string;

class Channel;
class LaRPCFactory;

/*struct hash_channel {
  int operator()(const Channel& c) const {
    hash<const char*> h;
    return h(c.GetChannelId().c_str());
  }
};
*/
struct eq_channel_ptr {
  bool operator()(Channel* const a, Channel* const b) const;
};

class Multiplexer {
 private:
  Multiplexer(Socket* s);
  friend class LaRPCFactory;

 public:  
  void NewChannel(DSA* local_identity,
                  DSA* requested_remote_identity,
                  function1<void,Channel*> callback);

  inline bool IsShutdown() {
    return is_shut_down_;
  }

  void ShutdownChannel(Channel* c);
  void Shutdown();
  void AsyncShutdown();

  string Describe();

 private:
  mutex channel_lock_;
  hash_map<string, Channel*, hash<string>, eq_channel_ptr> channels_;
  volatile bool disallow_new_channels_;

  void SendChannelSetup();
  
  friend class Channel;

  // All messages should be sent with this function. It appropriately
  // sends the packet size before sending any message.
  void SendMessage(const string& msg);

  // The message reception chain.
  // Call ReceiveOneMessage once to initiate asynchronous reception.
  // A protocol buffer will be received and deserialized, and then
  // ProcessOneMessage will be called. Once processing is complete, the
  // ReceiveOneMessage will be called again, unless the socket is unable
  // to receive more messages.
  virtual void StartReceiveLoop();
  void MessageLengthReceived(int* message_length, const error_code& error);
  void MessageReceived(int* message_length,
                       uint8_t* message_buffer,
                       const error_code& error);

  // If an ASIO error occurs, it will be handled by this function. It MAY
  // shutdown the multiplexer, depending on the seriousness of the error,
  // or it may take some corrective action. This function should be called
  // from a failure path; in other words, they should exit gracefully but
  // expect to fail if this function is called in their code path.
  virtual void HandleErrorCondition(const error_code& error);
  
  // Processes a message coming off the wire.
  virtual void ProcessOneMessage(const string& message);

  // This function should only be called once by AsyncShutdown(), and does
  // the actual work of shutting down the mux.
  void AsyncShutdownOnce();

  Socket* socket_;
  async_ostream ostream_;

  // Shutdown semantics; Shutdown calls
  // shutdown_wait_.wait(shutdown_lock_, is_shut_down_)
  mutex shutdown_lock_;
  condition_variable shutdown_wait_;
  volatile bool is_shut_down_;

  volatile bool is_shutting_down_;

  LaRPCFactory* factory_;
};

} // namespace larpc

#endif // _MULTIPLEXER_H


