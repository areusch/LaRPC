/**
 * channel.cc - LaRPC Channel
 * Copyright (C) 2010 Andrew Reusch <areusch@gmail.com>
 *
 */

#include "channel.h"
#include <boost/thread/mutex.hpp>
#include <boost/interprocess/sync/scoped_lock.hpp>
#include "multiplexer.h"
#include "proto/larpc.pb.h"

namespace larpc {

using ::boost::mutex;
using ::boost::interprocess::scoped_lock;

void Channel::SendMessage(const string& msg) {
  mux_->SendMessage(msg);
}

void Channel::Shutdown() {
  Shutdown(true);
}

void Channel::Shutdown(bool send_control_message) {
  {
    scoped_lock<mutex> lock(active_lock_);
    if (!active_)
      return;
    
    active_ = false;
  }

  if (send_control_message) {
    ChannelControl control;
    control.add_close_channel_id(GetChannelId());
    SendMessage(control.SerializeAsString());
  }
}

} // namespace larpc
