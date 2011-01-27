/**
 * network_mock.cc - Mock implementation of the LaRPC Network abstraction
 * Copyright (C) 2010 Andrew Reusch <areusch@gmail.com>
 *
 */

#ifndef _TEST_NETWORK_H
#define _TEST_NETWORK_H

#include "network.h"
#include <boost/asio.hpp>

namespace larpc {
namespace test {

using ::boost::asio::ip::tcp;

using ::larpc::Socket;
using ::larpc::ServerSocket;
using ::larpc::Network;

class MockSocket : public Socket {
 public:
  MOCK_METHOD2(Write, void(::boost::asio::const_buffers_1, TransferCallback));
  MOCK_METHOD2(Read, void(::boost::asio::mutable_buffers_1, TransferCallback));

  MOCK_METHOD0(Close, void());
};

class MockServerSocket : public ServerSocket {
 public:
  MOCK_METHOD1(Accept, void(AcceptCallback));
  MOCK_METHOD0(Close, void());
};

class MockNetwork : public Network {
 public:
  MOCK_METHOD1(Listen, ServerSocket*(const tcp::endpoint&));
  MOCK_METHOD2(Connect, larpc::Socket*(const tcp::endpoint&, ConnectCallback));
};

} // namespace test
} // namespace larpc

#endif // _TEST_NETWORK_H
