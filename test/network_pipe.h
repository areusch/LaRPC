/**
 * network_pipe.h - Piped Network Impl for testing.
 * Copyright (C) 2010 Andrew Reusch <areusch@gmail.com>
 *
 */

#ifndef _TEST_NETWORK_PIPE_H
#define _TEST_NETWORK_PIPE_H

#include "network.h"
#include <iostream>
#include <map>
#include <queue>
#include <set>
#include <vector>
#include <boost/asio.hpp>
#include <boost/function.hpp>
#include <boost/thread.hpp>

namespace larpc {
namespace test {

using ::boost::asio::ip::address;
using ::boost::asio::ip::tcp;
using ::boost::asio::streambuf;
using ::boost::function0;
using ::boost::mutex;
using ::std::istream;
using ::std::ostream;
using ::std::map;
using ::std::pair;
using ::std::queue;
using ::std::set;
using ::std::vector;

class PipeNetwork;
class PipeServerSocket;
class PipeSocket;

class PipeSubnet : public ::boost::thread {
 public:
  PipeSubnet(address& network, unsigned int mask);
  virtual ~PipeSubnet();

  address GetLocalAddress(unsigned int host_id);

  PipeNetwork* NewNode(address& address);

  void RemoveNode(address& address);

  PipeNetwork* operator[](address& address);

  void RunInThread(function0<void> func);

  void Shutdown();

 private:
  void Runner();
  
  address network_;
  unsigned int mask_;

  ::boost::mutex nodes_guard_;
  typedef map<address, PipeNetwork*> NodeMap;
  NodeMap nodes_;
  
  ::boost::mutex op_lock_;
  volatile bool shutdown_;
  ::boost::condition_variable op_cond_;
  vector<function0<void> > ops_;
};

class PipeSocket : public Socket {
 protected:
  PipeSocket(PipeNetwork* network, const tcp::endpoint& local_ep);
  PipeSocket(PipeNetwork* network, const tcp::endpoint& local_ep, PipeSocket* other);

  void Bind(PipeSocket* other);
  
  void WriteToBuffer(::boost::asio::const_buffers_1 b, TransferCallback cb);
  void ShutdownBoth();
  void BindAndConnect(tcp::endpoint target, PipeSubnet* net, ConnectCallback cb);
  void ReadBuffer(::boost::asio::mutable_buffers_1 b, TransferCallback cb);  
 public:
  virtual ~PipeSocket();
  virtual bool IsOpen();
  virtual tcp::endpoint GetLocalEndpoint();
  virtual tcp::endpoint GetRemoteEndpoint();
  
  virtual void Write(::boost::asio::const_buffers_1 b, TransferCallback cb);
  virtual void Read(::boost::asio::mutable_buffers_1 b, TransferCallback cb);
  
  virtual void Close();
 protected:
  friend class PipeNetwork;
  friend class PipeServerSocket;

  volatile bool shutdown_;
  PipeNetwork* local_network_;
  PipeSocket* remote_;
  tcp::endpoint local_ep_;
  streambuf buffer_;
  ostream out_;
  istream in_;
};

class PipeServerSocket : public ServerSocket {
 protected:
  PipeServerSocket(const tcp::endpoint& ep, PipeNetwork* network);

 public:
  virtual ~PipeServerSocket();

  virtual void Accept(AcceptCallback cb);
  virtual bool IsOpen();
  virtual tcp::endpoint GetLocalEndpoint();
  virtual void Close();

  void Submit(PipeSocket* sock, ConnectCallback cb);

 protected:
  void DoAccept(PipeSocket* remote, ConnectCallback remote_cb, AcceptCallback cb);

  friend class PipeNetwork;
  volatile bool open_;
  
  tcp::endpoint local_endpoint_;
  PipeNetwork* network_;

  mutex queue_guard_;

  queue<pair<PipeSocket*, ConnectCallback> > accept_queue_;
  queue<AcceptCallback> cb_queue_;
};

class PipeNetwork : public Network {
 protected:
  PipeNetwork(PipeSubnet* subnet, address& address);

  // Callee must hold sockets_guard_
  int FindFreeLocalPort();
 public:
  virtual ~PipeNetwork();

  virtual ServerSocket* Listen(const tcp::endpoint& ep);
  virtual Socket* Connect(const tcp::endpoint& ep, ConnectCallback cb);
  
  PipeServerSocket* GetSocketAt(unsigned int port);

  void Shutdown();

 protected:
  friend class PipeServerSocket;
  friend class PipeSocket;
  friend class PipeSubnet;

  PipeSubnet* subnet_;
  address local_address_;
  ::boost::mutex sockets_guard_;
  bool shutdown_;
  typedef map<unsigned int, PipeSocket*> SocketsMap;
  typedef map<unsigned int, PipeServerSocket*> ServerSocketsMap;
  SocketsMap sockets_;
  ServerSocketsMap servers_;
  unsigned int last_used_port_;
};

} // namespace test
} // namespace larpc

#endif // _TEST_NETWORK_PIPE_H


