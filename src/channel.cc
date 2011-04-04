/**
 * channel.cc - LaRPC Channel
 * Copyright (C) 2010 Andrew Reusch <areusch@gmail.com>
 *
 */

#include "channel.h"
#include <boost/interprocess/sync/scoped_lock.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/bind.hpp>
#include <glog/logging.h>
#include <openssl/err.h>
#include "openssl.h"
#include "multiplexer.h"
#include "proto/larpc.pb.h"

#define SSL_TRANSFER_BIO_BUFFER_SIZE_BYTES   4096

namespace larpc {

using ::boost::asio::buffer_cast;
using ::boost::asio::buffer_size;
using ::boost::interprocess::scoped_lock;
using ::boost::mutex;

Channel::Channel(const string& channel_id, Multiplexer* mux) :
    active_(true), ssl_ctx_(NULL), ssl_(NULL), is_server_(false), ssl_bio_(NULL),
    transfer_bio_(NULL), io_buffer_(bind(&Channel::WriteDataFunction, this, _1, _2)),
    write_buffer_ring_(NULL, 0), channel_id_(channel_id), mux_(mux) {}

Channel::Channel(const string& channel_id,
                 SSL_CTX* ssl_ctx,
                 bool is_server,
                 Multiplexer* mux) :
    active_(true), ssl_ctx_(ssl_ctx), ssl_(NULL), is_server_(is_server),
    ssl_bio_(NULL), transfer_bio_(NULL), io_buffer_(bind(&Channel::WriteDataFunction, this, _1, _2)),
    write_buffer_ring_(NULL, 0), channel_id_(channel_id), mux_(mux) {}

Channel::~Channel() {
  if (active_)
    Shutdown(false);
}

void Channel::SetupSSL() {
  if (ssl_ || !ssl_ctx_)
    return;

  if (!BIO_new_bio_pair(&ssl_bio_,
                        SSL_TRANSFER_BIO_BUFFER_SIZE_BYTES,
                        &transfer_bio_,
                        SSL_TRANSFER_BIO_BUFFER_SIZE_BYTES)) {
    LOG(ERROR) << "Cannot create BIO pair for SSL";
    return;
  }

  ssl_ = SSL_new(ssl_ctx_);
  SSL_set_bio(ssl_, ssl_bio_, ssl_bio_);

  int ret;
  if (is_server_)
    ret = SSL_accept(ssl_);
  else
    ret = SSL_connect(ssl_);

  MaybeTransferSSLBuffer(SSL_get_error(ssl_, ret));
}

bool Channel::MaybeTransferSSLBuffer(int ssl_error) {
  if (ssl_error != SSL_ERROR_WANT_WRITE)
    return false;

  char transfer_buf[SSL_TRANSFER_BIO_BUFFER_SIZE_BYTES];
  int bytes_read = BIO_read(transfer_bio_,
                            (void*) transfer_buf,
                            SSL_TRANSFER_BIO_BUFFER_SIZE_BYTES);
  if (bytes_read < 0)
    return false;
  else if (bytes_read == 0)
    return true;

  proto::MultiplexerMessage msg;
  msg.set_channel_id(channel_id_);
  msg.set_raw_data(string(transfer_buf, bytes_read));

  string out_msg;
  if (!msg.SerializeToString(&out_msg))
    return false;

  mux_->SendMessage(out_msg);

  return true;
}

void Channel::WriteMoreSSLData() {
  for (; current_write_buffer_ != end_write_buffer_;
       current_write_buffer_++, current_byte_position_ = 0) {
    int bytes_written = SSL_write(
      ssl_,
      (const void*) (buffer_cast<const char*>(*current_write_buffer_) + current_byte_position_),
      buffer_size(*current_write_buffer_) + current_byte_position_);

    if (bytes_written == buffer_size(*current_write_buffer_)) {
      continue;
    } else if (bytes_written > 0) {
      current_byte_position_ = bytes_written;
    } else {
      int ssl_error = SSL_get_error(ssl_, bytes_written);
      if (MaybeTransferSSLBuffer(ssl_error))
        continue;
      else if (ssl_error == SSL_ERROR_WANT_READ)
        return;
      else
        HandleSSLError(ssl_error);
    }
  }

  size_t bytes_written = bytes_written_;
  bytes_written_ = 0;
  current_write_cb_(make_error_code(boost::system::errc::success), bytes_written);
}

void Channel::HandleSSLError(int error_code) {

  LOG(ERROR) << "SSL error on channel " << this << ":" << GetSSLErrorString(error_code)
             << ". Channel will close.";

  Shutdown();
}

void Channel::WriteDataFunction(::boost::asio::const_buffer buf,
                                async_ostream::write_callback cb) {
  if (ssl_) {
    write_buffer_ring_ = buffer(buf);
    current_write_buffer_ = write_buffer_ring_.begin();
    end_write_buffer_ = write_buffer_ring_.end();
    current_write_cb_ = cb;

    WriteMoreSSLData();
  } else {
    mux_->ostream_.write(buf);
    // TODO CB
  }
}

void Channel::HandleMessage(const proto::MultiplexerMessage& msg) {
  if (msg.has_raw_data()) {
    BIO_write(transfer_bio_, msg.raw_data().c_str(), msg.raw_data().size());
    WriteMoreSSLData();
  }
}

void Channel::SendMessage(const string& msg) {
  SetupSSL();

  io_buffer_.write(msg);
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
    proto::ChannelControl control;
    control.add_close_channel_id(GetChannelId());
    SendMessage(control.SerializeAsString());
  }
}

} // namespace larpc
