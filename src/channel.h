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
#include <openssl/ssl.h>
#include "async_iostream.h"
#include "proto/larpc.pb.h"
#include "util.h"

namespace larpc {

using ::std::string;
using ::boost::mutex;

class Multiplexer;
class Principle;

class Channel {
 protected:
  /**
   * NOTE: Channel objects should be constructed _after_ the channel setup messages have been
   *       sent back and forth. An existing, closed Channel indicates that the channel did
   *       exist sometime in the past, but it has now been deceased.
   */

  /**
   * Establish an unencrypted channel with the given channel id.
   *
   * @param channel_id The channel id of the new channel.
   */
  Channel(const string& channel_id, Multiplexer* mux);

  /**
   * Establish a potentially-encrypted channel between two machines; data is
   * encrypted with the machine keys.
   *
   * @param channel_id The channel id of the new channel.
   * @param ctx If not NULL, the SSL CTX to use when setting up the channel
   */
  Channel(const string& channel_id,
          SSL_CTX* ctx,
          bool is_server,
          Multiplexer* mux);

  virtual ~Channel();

 private:
  friend class Multiplexer;

 public:
  inline string GetChannelId() const {
    return channel_id_;
  }

  // Calls Shutdown(true);
  virtual void Shutdown();

 private:
  // Private function which has access to Multiplexer's async
  // iostream.
  void SendMessage(const string& msg);

  // Shutdown and optionally send control message.
  virtual void Shutdown(bool send_control_message);

  bool MaybeTransferSSLBuffer(int error_code);

  // Writes SSL data until the SSL layer indicates an error or the data was
  // transferred successfully.
  void WriteMoreSSLData();
  void SetupSSL();

  void WriteDataFunction(::boost::asio::const_buffer buf,
                         async_ostream::write_callback cb);

  virtual void HandleMessage(const proto::MultiplexerMessage& msg);

  void HandleSSLError(int error_code);

  mutex active_lock_;
  bool active_;
  SSL_CTX* ssl_ctx_;
  SSL* ssl_;
  bool is_server_;
  BIO* ssl_bio_;
  BIO* transfer_bio_;

  string channel_id_;

  async_ostream io_buffer_;
  ::boost::asio::const_buffers_1 write_buffer_ring_;
  ::boost::asio::const_buffers_1::const_iterator current_write_buffer_;
  ::boost::asio::const_buffers_1::const_iterator end_write_buffer_;
  async_ostream::write_callback current_write_cb_;

  size_t current_byte_position_;
  size_t bytes_written_;

  Multiplexer* mux_;
 private:
  DISALLOW_EVIL_CONSTRUCTORS(Channel);
};

} // namespace larpc

#endif // _CHANNEL_H


