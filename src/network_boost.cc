/**
 * network_boost.cc - Boost implementation of a network socket
 * Copyright (C) 2010 Andrew Reusch <areusch@gmail.com>
 *
 */

#include "network_boost.h"
#include <memory>
#include <boost/bind.hpp>
#include <glog/logging.h>

namespace larpc {

using ::std::auto_ptr;

BoostSocket::BoostSocket(io_service& service) : s_(service) {}

tcp::endpoint BoostSocket::GetLocalEndpoint() {
  return s_.local_endpoint();
}

tcp::endpoint BoostSocket::GetRemoteEndpoint() {
  return s_.remote_endpoint();
}

bool BoostSocket::IsOpen() {
  return s_.is_open();
}

void BoostSocket::Write(::boost::asio::const_buffer b, TransferCallback cb) {
  boost::asio::async_write(s_, buffer(b), cb);
}

void BoostSocket::Read(::boost::asio::mutable_buffer b, TransferCallback cb) {
  boost::asio::async_read(s_, buffer(b), cb);
}

void BoostSocket::Close() {
  s_.close();
}

BoostSocket::~BoostSocket() {
  Close();
}

BoostServerSocket::BoostServerSocket(io_service& io) :
    acceptor_(io), service_( io) {}

bool BoostServerSocket::Bind(const tcp::endpoint& ep) {
  error_code ec;
  acceptor_.bind(ep, ec);

  return !ec;
}

bool BoostServerSocket::IsOpen() {
  return acceptor_.is_open();
}

tcp::endpoint BoostServerSocket::GetLocalEndpoint() {
  return acceptor_.local_endpoint();
}

void BoostServerSocket::Close() {
  acceptor_.close();
}

void BoostServerSocket::Accept(AcceptCallback cb) {
  auto_ptr<BoostSocket> socket( new BoostSocket(service_) );
  acceptor_.async_accept(socket->s_,
                         bind(&BoostNetwork::HandleConnect,
                              (Socket*) socket.release(),
                              cb,
                              ::boost::asio::placeholders::error));
}

BoostServerSocket::~BoostServerSocket() {
  Close();
}

BoostNetwork::BoostNetwork(io_service& io) : io_(io) {}

Socket* BoostNetwork::Connect(const tcp::endpoint& ep, ConnectCallback cb) {
  auto_ptr<BoostSocket> new_socket(new BoostSocket(io_));

  new_socket->s_.async_connect(ep,
                               bind(&BoostNetwork::HandleConnect,
                                    new_socket.release(),
                                    cb,
                                    ::boost::asio::placeholders::error));
}

void BoostNetwork::HandleConnect(Socket* s, ConnectCallback cb, const error_code& ec) {
  cb(s, ec);
  if (ec) {
    delete s;
  }
}

ServerSocket* BoostNetwork::Listen(const tcp::endpoint& ep) {
  auto_ptr<BoostServerSocket> socket( new BoostServerSocket(io_) );
  if (socket->Bind(ep))
    return socket.release();

  return NULL;
}

BoostNetwork::~BoostNetwork() {
  io_.stop();
}

} // namespace larpc
