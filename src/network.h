/**
 * network.h - LaRPC network abstractions
 * Copyright (C) 2010 Andrew Reusch <areusch@gmail.com>
 *
 */

#ifndef _NETWORK_H
#define _NETWORK_H

#include <stdio.h>
#include <boost/asio.hpp>
#include <boost/function.hpp>

namespace larpc {

typedef ::boost::function2<void, const ::boost::system::error_code&, size_t> TransferCallback;

using ::boost::asio::ip::tcp;

class Socket {
 public:
  virtual ~Socket() {}

  virtual bool IsOpen() = 0;

  virtual tcp::endpoint GetLocalEndpoint() = 0;
  virtual tcp::endpoint GetRemoteEndpoint() = 0;

  virtual void Write(::boost::asio::const_buffer b, TransferCallback cb) = 0;
  virtual void Read(::boost::asio::mutable_buffer b, TransferCallback cb) = 0;

  virtual void Close() = 0;
};

typedef ::boost::function2<void, Socket*, const ::boost::system::error_code&> AcceptCallback;

class ServerSocket {
 public:
  virtual ~ServerSocket() {}

  virtual void Accept(AcceptCallback cb) = 0;

  virtual bool IsOpen() = 0;

  virtual tcp::endpoint GetLocalEndpoint() = 0;

  virtual void Close() = 0;
};

typedef ::boost::function2<void, Socket*, const boost::system::error_code&> ConnectCallback;

class Network {
 public:
  virtual ~Network() {}

  virtual ServerSocket* Listen(const tcp::endpoint& ep) = 0;

  virtual Socket* Connect(const tcp::endpoint& ep, ConnectCallback cb) = 0;
};

} // namespace larpc

#endif // _NETWORK_H


