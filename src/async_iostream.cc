/**
 * async_iostream.cc - Asynchronous IOStream.
 * Copyright (C) 2010 Andrew Reusch <areusch@gmail.com>
 *
 */

#include "async_iostream.h"
#include <boost/bind.hpp>
#include <boost/interprocess/sync/scoped_lock.hpp>

namespace larpc {

using ::boost::asio::buffer;
using ::boost::bind;
using ::boost::ref;
using ::boost::interprocess::scoped_lock;
using ::std::size_t;

async_ostream::async_ostream(write_function f) :
    write_(f), write_in_progress_(false) {}

void async_ostream::write(const string& s) {
  bool actuate_write = false;
  {
    scoped_lock<mutex> lock(buffer_lock_);

    if (!write_in_progress_) {
      write_in_progress_ = true;
      actuate_write = true;
    }
    buffer_.push(s);
  }

  if (actuate_write)
    write_(buffer(buffer_.front().data(), buffer_.front().size()), bind(&async_ostream::write_finished, ref(this), _1, _2));
}

void async_ostream::write_finished(const error_code& e, size_t bytes_written) {
  string s;

  {
    scoped_lock<mutex> lock(buffer_lock_);

    write_in_progress_ = false;
    buffer_.pop();

    if (!buffer_.size())
      return;

    write_in_progress_ = true;
  }

  write_(buffer(buffer_.front().data(), buffer_.front().size()), bind(&async_ostream::write_finished, ref(this), ::boost::asio::placeholders::error, _2));
}

} // namespace larpc

