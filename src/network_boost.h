/**
 * network_boost.h - Boost implementation of networking abstractions.
 * Copyright (C) 2010 Andrew Reusch <areusch@gmail.com>
 *
 */

#ifndef _SRC_NETWORK_BOOST_H
#define _SRC_NETWORK_BOOST_H

#include <boost/asio.hpp>
#include "network.h"

namespace larpc {

using ::boost::asio::ip::tcp;
using ::boost::asio::io_service;
using ::boost::system::error_code;

using ::std::auto_ptr;

class BoostSocket : public Socket {
  public:
  tcp::socket s_;

  BoostSocket(io_service& service);

  virtual tcp::endpoint GetLocalEndpoint();
  virtual tcp::endpoint GetRemoteEndpoint();

  virtual bool IsOpen();

  virtual void Write(::boost::asio::const_buffer b, TransferCallback cb);
  virtual void Read(::boost::asio::mutable_buffer b, TransferCallback cb);

  virtual void Close();

  virtual ~BoostSocket();
};

class BoostServerSocket : public ServerSocket {
 protected:
  tcp::acceptor acceptor_;
  io_service& service_;

 public:
  BoostServerSocket(io_service& io);

  bool Bind(const tcp::endpoint& ep);

  virtual tcp::endpoint GetLocalEndpoint();

  virtual bool IsOpen();

  virtual void Close();
  virtual void Accept(AcceptCallback cb);
  virtual ~BoostServerSocket();
};

class BoostNetwork : public Network {
 public:
  BoostNetwork(io_service& io);
  virtual ~BoostNetwork();

  virtual ServerSocket* Listen(const tcp::endpoint& ep);
  virtual Socket* Connect(const tcp::endpoint& ep, ConnectCallback cb);

 private:
  static void HandleConnect(Socket* s, ConnectCallback cb, const error_code& ec);
  friend class BoostServerSocket;
  io_service& io_;
};



} // namespace larpc

#endif // _SRC_NETWORK_BOOST_H


