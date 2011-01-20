/**
 * channel.h - LaRPC channel
 * Copyright (C) 2010 Andrew Reusch <areusch@gmail.com>
 *
 */

#ifndef _CHANNEL_H
#define _CHANNEL_H

#include <string>
#include <boost/asio.hpp>
#include <boost/thread/mutex.hpp>
#include "proto/larpc.pb.h"
#include "util.h"

namespace larpc {

using ::std::string;
using ::boost::mutex;

class Multiplexer;
class Principle;

class Channel {
 private:
  Channel(Principle* local_identity,
          Principle* remote_identity);

  friend class Multiplexer;
  
 public:
  inline string GetChannelId() const {
    return local_channel_id_ + remote_channel_id_;
  }

  bool SendRPC(const RPCRequest& request);

  // Calls Shutdown(true);
  void Shutdown();

 private:
  // Private function which has access to Multiplexer's async
  // iostream.
  void SendMessage(const string& msg);

  // Shutdown and optionally send control message.
  void Shutdown(bool send_control_message);

  mutex active_lock_;
  bool active_;
  Multiplexer* mux_;
  string local_channel_id_;
  string remote_channel_id_;

 private:
  DISALLOW_EVIL_CONSTRUCTORS(Channel);
};

} // namespace larpc

#endif // _CHANNEL_H


