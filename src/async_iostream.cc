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
using ::boost::asio::buffer_cast;
using ::boost::bind;
using ::boost::ref;
using ::boost::interprocess::scoped_lock;
using ::std::make_pair;
using ::std::size_t;

async_ostream::async_ostream(write_function f) :
    write_(f), write_in_progress_(false) {}

void async_ostream::write(const const_buffer& b, bool take_ownership) {
  write(const_buffers_1(b), take_ownership);
}

void async_ostream::write(const const_buffers_1& b, bool take_ownership) {
  if (b.begin() == b.end())
    return;

  bool actuate_write = false;
  {
    scoped_lock<mutex> lock(buffer_lock_);

    if (!write_in_progress_) {
      write_in_progress_ = true;
      actuate_write = true;
    }
    for (const_buffers_1::const_iterator it = b.begin(); it != b.end(); it++)
      buffer_.push(make_pair<const_buffer, bool>(*it, take_ownership));
  }

  if (actuate_write)
    write_(buffer_.front().first, bind(&async_ostream::write_finished, ref(this), _1, _2));
}

void async_ostream::write(const string& s) {
  char* local_buffer = new char[s.size()];
  strncpy(local_buffer, s.c_str(), s.size());

  write(buffer(local_buffer, s.size()), true);
}

void async_ostream::write_finished(const error_code& e, size_t bytes_written) {
  string s;

  {
    scoped_lock<mutex> lock(buffer_lock_);

    write_in_progress_ = false;
    if (buffer_.front().second) // do we have ownership?
      delete buffer_cast<const char*>(buffer_.front().first);

    buffer_.pop();

    if (!buffer_.size())
      return;

    write_in_progress_ = true;
  }

  write_(buffer_.front().first,
         bind(&async_ostream::write_finished,
              ref(this),
              ::boost::asio::placeholders::error,
              _2));
}

} // namespace larpc

