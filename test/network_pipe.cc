/**
 * network_pipe.cc - Piped Network Impl for Testing
 * Copyright (C) 2010 Andrew Reusch <areusch@gmail.com>
 *
 */

#include "network_pipe.h"
#include <memory>
#include <boost/asio/buffer.hpp>
#include <boost/foreach.hpp>
#include <boost/interprocess/sync/scoped_lock.hpp>
#include <boost/system/error_code.hpp>

namespace larpc {
namespace test {

using ::boost::asio::ip::address_v4;
using ::boost::asio::buffer_cast;
using ::boost::asio::buffer_size;
using ::boost::interprocess::scoped_lock;
using ::boost::system::error_code;
using ::boost::bind;
using ::boost::mutex;
using ::boost::unique_lock;
using ::std::auto_ptr;
using ::std::make_pair;
using ::std::pair;

PipeSubnet::PipeSubnet(address& network, unsigned int mask) :
    ::boost::thread(bind(&PipeSubnet::Runner, this)), network_(network), mask_(mask) {}

PipeSubnet::~PipeSubnet() {
  typedef pair<address, PipeNetwork*> NodeEntry;
  BOOST_FOREACH(NodeEntry p, nodes_) {
    p.second->Shutdown();
  }
}

address PipeSubnet::GetLocalAddress(unsigned int host_id) {
  return address(address_v4((network_.to_v4().to_ulong() & ~(mask_ - 1)) | ((mask_ - 1) & host_id)));
}

PipeNetwork* PipeSubnet::NewNode(address& address) {
  scoped_lock<mutex> lock(nodes_guard_);

  auto_ptr<PipeNetwork> new_node(new PipeNetwork(this, address));
  pair<NodeMap::iterator, bool> result = nodes_.insert(make_pair(address, new_node.get()));

  if (!result.second)
    return NULL;

  return new_node.release();
}

void PipeSubnet::RemoveNode(address& address) {
  scoped_lock<mutex> lock(nodes_guard_);

  NodeMap::iterator it = nodes_.find(address);
  if (it == nodes_.end())
    return;

  auto_ptr<PipeNetwork> removed_node((*it).second);

  nodes_.erase(it);
  removed_node->Shutdown();
}

PipeNetwork* PipeSubnet::operator[](address& address) {
  scoped_lock<mutex> lock(nodes_guard_);

  NodeMap::iterator it = nodes_.find(address);
  if (it == nodes_.end())
    return NULL;
  return (*it).second;
}

void PipeSubnet::RunInThread(function0<void> func) {
  {
    scoped_lock<mutex> lock(op_lock_);
    ops_.push_back(func);
  }

  op_cond_.notify_one();
}

void PipeSubnet::Shutdown() {
  scoped_lock<mutex> lock(op_lock_);
  shutdown_ = true;
  op_cond_.notify_one();
}

void PipeSubnet::Runner() {
  while (!shutdown_) {
    function0<void> func;
    {
      unique_lock<mutex> lock(op_lock_);
      if (ops_.size() > 0) {
        func = ops_[ops_.size() - 1];
        ops_.pop_back();
      } else {
        op_cond_.wait(lock);
      }
    }
    func();
  }
}

PipeNetwork::PipeNetwork(PipeSubnet* subnet, address& address) :
    local_address_(address), subnet_(subnet), shutdown_(false),
    last_used_port_(65535) {}

PipeNetwork::~PipeNetwork() {
  Shutdown();
}

ServerSocket* PipeNetwork::Listen(const tcp::endpoint& ep) {
  scoped_lock<mutex> lock(sockets_guard_);

  tcp::endpoint real_ep = ep;
  if (ep.address() == address(address_v4(0)))
    real_ep = tcp::endpoint(local_address_, ep.port());

  auto_ptr<PipeServerSocket> new_socket(new PipeServerSocket(real_ep, this));

  pair<ServerSocketsMap::iterator,bool> it =
    servers_.insert(make_pair(real_ep.port(), new_socket.get()));

  if (!it.second)
    return NULL;

  return new_socket.release();
}

int PipeNetwork::FindFreeLocalPort() {
  unsigned int start_next_free_port = last_used_port_;
  while (--last_used_port_ != start_next_free_port) {
    if (sockets_.find(last_used_port_) == sockets_.end() &&
        servers_.find(last_used_port_) == servers_.end())
      break;

    if (last_used_port_ < 0)
      last_used_port_ = 65536;
  }

  if (last_used_port_ == 0) {
    last_used_port_ = 65536;
    return -1;
  }

  if (start_next_free_port == last_used_port_)
    return -1;

  return last_used_port_;
}

Socket* PipeNetwork::Connect(const tcp::endpoint& ep, ConnectCallback cb) {
  scoped_lock<mutex> lock(sockets_guard_);

  int local_port = FindFreeLocalPort();
  if (local_port == -1)
    return NULL;

  tcp::endpoint local_ep(local_address_, last_used_port_);
  auto_ptr<PipeSocket> new_socket(new PipeSocket(this, local_ep));

  sockets_.insert(make_pair(last_used_port_, new_socket.get()));

  subnet_->RunInThread(bind(&PipeSocket::BindAndConnect,
                            new_socket.get(),
                            ep,
                            subnet_,
                            cb));

  return new_socket.release();
}

void PipeNetwork::Shutdown() {
  sockets_guard_.lock();
  shutdown_ = true;

  SocketsMap shadow_map(sockets_.begin(), sockets_.end());
  ServerSocketsMap server_shadow_map(servers_.begin(), servers_.end());
  sockets_guard_.unlock();

  typedef pair<unsigned int, PipeSocket*> ShadowMapEntry;
  BOOST_FOREACH(ShadowMapEntry p, shadow_map) {
    p.second->ShutdownBoth();
  }

  typedef pair<unsigned int, PipeServerSocket*> ServerShadowMapEntry;
  BOOST_FOREACH(ServerShadowMapEntry p, server_shadow_map) {
    p.second->Close();
  }
}

PipeServerSocket* PipeNetwork::GetSocketAt(unsigned int port) {
  scoped_lock<mutex> lock(sockets_guard_);

  ServerSocketsMap::iterator it = servers_.find(port);
  if (it == servers_.end())
    return NULL;

  return (*it).second;
}

PipeSocket::PipeSocket(PipeNetwork* network, const tcp::endpoint& local_ep) :
    shutdown_(false), local_network_(network), remote_(NULL), local_ep_(local_ep),
    out_(&buffer_), in_(&buffer_) {}

PipeSocket::PipeSocket(PipeNetwork* network,
                       const tcp::endpoint& local_ep,
                       PipeSocket* other) :
    shutdown_(false), local_network_(network), remote_(other), local_ep_(local_ep),
    out_(&buffer_), in_(&buffer_) {}

PipeSocket::~PipeSocket() {
  ShutdownBoth();
}

void PipeSocket::Bind(PipeSocket* other) {
  remote_ = other;
}

void PipeSocket::WriteToBuffer(::boost::asio::const_buffers_1 b, TransferCallback cb) {
  if (!shutdown_) {
    unsigned long bytes_transferred = 0;
    for (::boost::asio::const_buffers_1::const_iterator it = b.begin();
         it != b.end();
         it++) {
      out_.write(buffer_cast<const char*>(*it), buffer_size(*it));
      bytes_transferred += buffer_size(*it);
    }
    cb(error_code(::boost::system::errc::success,
                  ::boost::system::system_category),
       bytes_transferred);
  } else {
    cb(error_code(::boost::system::errc::connection_reset,
                  ::boost::system::system_category),
      0);
  }
}

void PipeSocket::ShutdownBoth() {
  if (shutdown_)
    return;

  if (remote_)
    remote_->ShutdownBoth();

  shutdown_ = true;
}

bool PipeSocket::IsOpen() {
  return remote_ && !shutdown_;
}

void PipeSocket::BindAndConnect(tcp::endpoint target, PipeSubnet* subnet, ConnectCallback cb) {
  address target_ip = target.address();
  PipeNetwork* endpoint = (*subnet)[target_ip];

  if (!endpoint) {
    cb(this, error_code(::boost::system::errc::host_unreachable, ::boost::system::system_category));
    return;
  }

  PipeServerSocket* server = endpoint->GetSocketAt(target.port());
  if (!server || !server->IsOpen()) {
    cb(this, error_code(::boost::system::errc::connection_refused,
                        ::boost::system::system_category));
    return;
  }

  server->Submit(this, cb);
}

void PipeSocket::Write(::boost::asio::const_buffer b, TransferCallback cb) {
  if (!remote_) {
    cb(error_code(::boost::system::errc::bad_file_descriptor,
                  ::boost::system::system_category),
       0);
    return;
  }

  local_network_->subnet_->RunInThread(bind(&PipeSocket::WriteToBuffer,
                                            remote_,
                                            buffer(b),
                                            cb));
}

void PipeSocket::Read(::boost::asio::mutable_buffer b, TransferCallback cb) {
  local_network_->subnet_->RunInThread(bind(&PipeSocket::ReadBuffer,
                                            this,
                                            buffer(b),
                                            cb));
}

void PipeSocket::ReadBuffer(::boost::asio::mutable_buffers_1 b, TransferCallback cb) {
  if (!buffer_.size()) {
    if (shutdown_) {
      cb(error_code(::boost::system::errc::connection_reset,
                    ::boost::system::system_category),
         0);
    } else {
      cb(error_code(::boost::system::errc::success,
                    ::boost::system::system_category),
         0);
    }
    return;
  }

  unsigned long bytes_transferred = 0;
  for (::boost::asio::mutable_buffers_1::const_iterator it = b.begin();
       it != b.end();
       it++) {
    in_.get(buffer_cast<char*>(*it), buffer_size(*it));
    if (!in_.gcount())
      break;

    bytes_transferred += in_.gcount();
  }

  cb(error_code(::boost::system::errc::success,
                ::boost::system::system_category),
     bytes_transferred);
}

void PipeSocket::Close() {
  ShutdownBoth();
}

tcp::endpoint PipeSocket::GetLocalEndpoint() {
  return local_ep_;
}

tcp::endpoint PipeSocket::GetRemoteEndpoint() {
  if (remote_)
    return remote_->local_ep_;

  return tcp::endpoint(address(address_v4(0)), 0);
}

PipeServerSocket::PipeServerSocket(const tcp::endpoint& ep, PipeNetwork* network) :
    open_(true), local_endpoint_(ep), network_(network) {}

PipeServerSocket::~PipeServerSocket() {
  Close();
}

void PipeServerSocket::Accept(AcceptCallback cb) {
  scoped_lock<mutex> lock(queue_guard_);

  if (!accept_queue_.empty()) {
    pair<PipeSocket*, ConnectCallback> next = accept_queue_.front();
    accept_queue_.pop();
    lock.unlock();

    network_->subnet_->RunInThread(bind(&PipeServerSocket::DoAccept,
                                        this,
                                        next.first,
                                        next.second,
                                        cb));
  } else {
    cb_queue_.push(cb);
  }
}

bool PipeServerSocket::IsOpen() {
  return open_;
}

tcp::endpoint PipeServerSocket::GetLocalEndpoint() {
  return local_endpoint_;
}

void PipeServerSocket::Close() {
  if (!open_)
    return;

  scoped_lock<mutex> lock(queue_guard_);
  while (!accept_queue_.empty()) {
    pair<PipeSocket*, ConnectCallback> it = accept_queue_.front();
    accept_queue_.pop();
    it.second(it.first, error_code(::boost::system::errc::connection_reset,
                                   ::boost::system::system_category));
  }

  while (!cb_queue_.empty()) {
    AcceptCallback cb = cb_queue_.front();
    cb_queue_.pop();
    cb(NULL, error_code(::boost::system::errc::connection_reset,
                        ::boost::system::system_category));
  }
}

void PipeServerSocket::Submit(PipeSocket* sock, ConnectCallback cb) {
  scoped_lock<mutex> lock(queue_guard_);

  if (!cb_queue_.empty()) {
    AcceptCallback accept_cb = cb_queue_.front();
    cb_queue_.pop();
    network_->subnet_->RunInThread(bind(&PipeServerSocket::DoAccept,
                                        this,
                                        sock,
                                        cb,
                                        accept_cb));
  } else {
    accept_queue_.push(make_pair(sock, cb));
  }
}

void PipeServerSocket::DoAccept(PipeSocket* remote,
                                ConnectCallback remote_cb,
                                AcceptCallback cb) {
  scoped_lock<mutex> lock(network_->sockets_guard_);

  int local_port = network_->FindFreeLocalPort();
  if (local_port < 0) {
    lock.unlock();
    remote_cb(remote, error_code(::boost::system::errc::connection_refused,
                                 ::boost::system::system_category));
    cb(NULL, error_code(::boost::system::errc::address_in_use,
                        ::boost::system::system_category));
    delete remote;
    return;
  }

  auto_ptr<PipeSocket> local(new PipeSocket(network_,
                                            tcp::endpoint(network_->local_address_, local_port),
                                            remote));

  network_->sockets_[local_port] = local.release();

  remote_cb(remote, error_code(::boost::system::errc::success,
                               ::boost::system::system_category));
  cb(network_->sockets_[local_port], error_code(::boost::system::errc::success,
                                                ::boost::system::system_category));
}


} // namespace test
} // namespace larpc

