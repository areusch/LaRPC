/**
 * framework.h - Test jigs for LaRPC unit tests.
 * Copyright (C) 2010 Andrew Reusch <areusch@gmail.com>
 *
 */

#ifndef _TEST_FRAMEWORK_H
#define _TEST_FRAMEWORK_H

#include <iostream>
#include <memory>
#include <set>
#include <boost/bind.hpp>
#include <gflags/gflags.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/text_format.h>

#include "proto/test_config.pb.h"
#include "larpc.h"
#include "network_mock.h"

// Fixme: needs DECLARE_flag and framework.cc!
DEFINE_string(test_config,
              "",
              "File name containing the test configuration.");

DEFINE_int32(test_base_port,
             0,
             "Base port to use for network communications.");

DEFINE_bool(use_mock_network,
            true,
            "Whether to use the mock network layer to connect nodes.");

namespace larpc {
namespace test {

using ::boost::asio::ip::address;
using ::boost::asio::ip::tcp;
using ::boost::bind;
using ::google::protobuf::io::FileInputStream;
using ::std::auto_ptr;
using ::std::endl;
using ::std::cerr;
using ::std::set;

class KeyGeneratorFunctor {
 public:
  KeyGeneratorFunctor() {}
  virtual ~KeyGeneratorFunctor() {}
  virtual char* Generate() = 0;
};

class MockKeyGenerator : public KeyGeneratorFunctor {
 public:
  MockKeyGenerator() {}
  virtual ~MockKeyGenerator() {}
  MOCK_METHOD0(Generate, char*());
};

template <int n>
class NWayTest : public testing::Test {
 protected:
  NWayTest() : base_port_(FLAGS_test_base_port) {
    int config_fd;

    if (FLAGS_test_config != "-") {
      config_fd = open(FLAGS_test_config.c_str(), O_RDONLY);
    } else {
      config_fd = STDIN_FILENO;
    }

    CHECK(config_fd >= 0) << "Cannot open configuration file: " << strerror(errno);
    
    {
      FileInputStream fis(config_fd);
      config_.Clear();
      CHECK(::google::protobuf::TextFormat::Merge(&fis, &config_))
        << "Cannot parse test configuration!";
    }

    if (config_fd != STDIN_FILENO)
      close(config_fd);
  }

  NWayTest(int base_port, const TestConfig& config) : base_port_(base_port) {
    config_.MergeFrom(config);
  }

  virtual ~NWayTest() {}
  
  virtual void SetUp() {
    address localhost = address::from_string("127.0.0.1");
    for (int i = 0; i < n; ++i) {
      VLOG(1) << "Bringing up node " << i;
      endpoints[i].reset(new tcp::endpoint(localhost, base_port_ + i));
      key_generators[i].reset(new MockKeyGenerator());
      network[i].reset(new MockNetwork());
      factory[i].reset(new LaRPCFactory(network[i].get(), *(endpoints[i]), bind(&KeyGeneratorFunctor::Generate, key_generators[n].get())));

      set<Principle*> principles;
      for (int j = 0; j < config_.nodes(i).principles_size(); ++j) {
        Principle* p = Principle::FromDescriptor(factory[i].get(),
                                                 config_.nodes(i).principles(j));
        if (p)
          principles.insert(p);
        else
          LOG(ERROR) << "Error loading principle " << j << " for node " << i;
      }
      
      CHECK(principles.size() > 0) << "Node " << i
                                   << " has no principles! Aborting test!";
      factory[i]->ReplacePrinciples(&principles);
    }
  }

  virtual void TearDown() {
    for (int i = 0; i < n; ++i) {
      VLOG(1) << "Tearing down node " << i;
      factory[i].reset(NULL);
      network[i].reset(NULL);
      key_generators[i].reset(NULL);
      endpoints[i].reset(NULL);
    }
  }

 protected:
  TestConfig config_;
  int base_port_;
  auto_ptr<tcp::endpoint> endpoints[n];
  auto_ptr<LaRPCFactory> factory[n];
  auto_ptr<MockNetwork> network[n];
  auto_ptr<MockKeyGenerator> key_generators[n];
};

} // namespace test
} // namespace larpc

#endif // _TEST_FRAMEWORK_H

