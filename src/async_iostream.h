/**
 * async_iostream.h - Asynchronous IOStream.
 * Copyright (C) 2010 Andrew Reusch <areusch@gmail.com>
 *
 */

#ifndef _ASYNC_IOSTREAM_H
#define _ASYNC_IOSTREAM_H

#include <queue>
#include <string>
#include <boost/asio.hpp>
#include <boost/function.hpp>
#include <boost/system/error_code.hpp>
#include <boost/thread/mutex.hpp>

namespace larpc {

using ::boost::asio::const_buffer;
using ::boost::asio::const_buffers_1;
using ::boost::function1;
using ::boost::function2;
using ::boost::mutex;
using ::boost::system::error_code;
using ::std::pair;
using ::std::string;
using ::std::queue;

class async_ostream {
 public:
  typedef function2<void, const error_code&, ::std::size_t> write_callback;
  typedef function2<void, ::boost::asio::const_buffer, write_callback> write_function;
  async_ostream(write_function f);

  /**
   * Write the data in the given buffer(s) to the underlying transport. If
   * take_ownership is true, delete's the underlying buffers as they are
   * written.
   */
  void write(const const_buffer& b, bool take_ownership = false);
  void write(const const_buffers_1& b, bool take_ownership = false);

  /**
   * Write the data in the given string to the underlying transport. If
   * take_ownership is true, makes a copy of the data, and deletes it when
   * the transfer is complete. If take_ownership is false, the caller assumes
   * responsibility to maintain the data buffer until it has been written.
   * For fun and profit, no callback is provided at the moment to notify clients
   * when data transmission is complete.
   *
   * @param s String containing data to write.
   */
  void write(const string& s);

 private:
  write_function write_;
  bool write_in_progress_;

  void write_finished(const error_code& e, size_t bytes_written);

  mutex buffer_lock_;
  queue<pair<const_buffer, bool> > buffer_;
};

} // namespace larpc

#endif // _ASYNC_IOSTREAM_H


