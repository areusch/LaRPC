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

using ::boost::function1;
using ::boost::function2;
using ::boost::mutex;
using ::boost::system::error_code;
using ::std::string;
using ::std::queue;

class async_ostream {
 public:
  typedef function2<void, const error_code&, ::std::size_t> write_callback;
  typedef function2<void, ::boost::asio::const_buffers_1, write_callback> write_function;
  async_ostream(write_function f);

  void write(const string& s);
  
 private:
  write_function write_;
  bool write_in_progress_;

  void write_finished(const error_code& e, size_t bytes_written);
  
  mutex buffer_lock_;
  queue<string> buffer_;
};

} // namespace larpc

#endif // _ASYNC_IOSTREAM_H


