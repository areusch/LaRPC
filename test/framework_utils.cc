/**
 * framework_utils.cc - Utility binary for the test framework.
 * Copyright (C) 2010 Andrew Reusch <areusch@gmail.com>
 *
 */

#include <fstream>
#include <iostream>
#include <gflags/gflags.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/text_format.h>
#include "proto/test_config.pb.h"
#include "crypto.h"
#include "test/framework.h"

using std::fstream;
using std::ostream;
using std::cerr;
using std::cout;
using std::endl;


DEFINE_bool(gen_test_config,
            false,
            "Generate a boilerplate test configuration containing randomized data for each node.");

DEFINE_int32(num_nodes,
             0,
             "Specifies the number of nodes to include in the test config.");

DEFINE_int32(num_principles_per_node,
             0,
             "Specifies the number of principles to generate per node.");

DEFINE_double(num_principles_per_node_stdev,
              0.0f,
              "Specifies the standard deviation in the number of principles per node.");

DEFINE_string(key_cipher,
              "DSA",
              "Specifies the short name of the cipher to use when generating "
              "public keys.");

DEFINE_uint64(key_size,
              512,
              "Specifies the number of bits in a generated key.");

namespace larpc {
namespace test {

Principle* GeneratePrinciple(PrincipleDescriptor* p, 
                             EVP_PKEY* machine_key, 
                             CryptoInterface* crypto, 
                             const string& principle_name) {
  KeygenParameters params;
  params.set_key_type(FLAGS_key_cipher);
  params.set_num_bits(FLAGS_key_size);

  EVP_PKEY* key;
  CHECK(crypto->GenerateKey(params, &key)) << "Cannot generate a key of type "
                                           << FLAGS_key_cipher
                                           << " with " << FLAGS_key_size
                                           << " bits.";
  
  string key_encoded;
  CHECK(CryptoInterface::PublicKeyToPKCS8String(key, &key_encoded))
    << "Cannot serialize newly-generated key!";

  CHECK(key_encoded.size() > 30) << "Key size not sufficient!";

  auto_ptr<Principle> principle(new Principle(key, principle_name));
  
  map<string,string> machine_name;
  machine_name["CN"] = "Machine " + principle_name;

  CHECK(principle->SignAdoptPrivateKey(crypto, key, 100, machine_name, machine_key)) <<
    "Can't sign/adopt private key!";
  principle->MergePublicPrivateData(p, crypto);
  return principle.release();
}

EVP_PKEY* GenerateMachineKey(CryptoInterface* crypto) {
  KeygenParameters params;
  params.set_key_type(FLAGS_key_cipher);
  params.set_num_bits(FLAGS_key_size);
  
  EVP_PKEY* key;
  CHECK(crypto->GenerateKey(params, &key)) << "Cannot generate a key of type "
                                           << FLAGS_key_cipher
                                           << " with " << FLAGS_key_size
                                           << " bits.";
  
  return key;
}  

void GenerateTestNode(NodeConfig* node, CryptoInterface* crypto) {
  int num_principles = 
    (float(rand()) * FLAGS_num_principles_per_node_stdev * 2 / RAND_MAX) +
    FLAGS_num_principles_per_node;

  EVP_PKEY* machine_key = GenerateMachineKey(crypto);
  CHECK(CryptoInterface::PublicKeyToPKCS8String(machine_key, node->mutable_machine_key())) <<
    "Unexpectedly cannot serialize machine public key!";
  
  CHECK(crypto->PrivateKeyToPKCS8String(machine_key, node->mutable_machine_private_key())) <<
    "Unexpectedly cannot serialize machine private key!";
  
  for (int i = 0; i < num_principles; ++i) {
    int principle_num_str_size_bytes = 15;
    char principle_num_str[principle_num_str_size_bytes];
    CHECK(snprintf(principle_num_str, principle_num_str_size_bytes, "%d", i) != 
          principle_num_str_size_bytes);
    GeneratePrinciple(node->add_principles(), machine_key, crypto, string("Principle ") + principle_num_str);
  }
}

bool GenerateTestConfig(TestConfig* config, CryptoInterface* crypto) {
  if (!FLAGS_num_principles_per_node || !FLAGS_num_nodes) {
    cerr << "You must specify both --num_principles_per_node and --num_nodes to "
         << "generate a boilerplate test configuration!" << endl;
    return false;
  }

  for (int i = 0; i < FLAGS_num_nodes; ++i) {
    GenerateTestNode(config->add_nodes(), crypto);
  }

  return true;
};

} // namespace test
} // namespace larpc

static time_t gettime_unix() {
  return time(NULL);
}

int main(int argc, char** argv) {
  google::InitGoogleLogging(argv[0]);

  {
    std::string usage = "LaRPC Test Framework Utility\nUsage:";
    usage += argv[0];
    usage += " --gen_test_config [options]\n\n"
      "Options are shown below.\n";
    
    google::SetUsageMessage(usage);
    google::ParseCommandLineFlags(&argc, &argv, true);
  }

  if (!FLAGS_gen_test_config) {
    google::ShowUsageWithFlags(argv[0]);
    return 2;
  }

  larpc::CryptoInterface crypto(0, gettime_unix);

  if (FLAGS_gen_test_config) {
    larpc::test::TestConfig config;
    if (!larpc::test::GenerateTestConfig(&config, &crypto))
      return 1;

    ostream* output_stream = &cout;
    if (FLAGS_test_config != "") {
      output_stream = new fstream(FLAGS_test_config.c_str(), 
                                  fstream::out | fstream::trunc);
      if (!output_stream || !((fstream*) output_stream)->is_open()) {
        LOG(ERROR) << "Unexpected error while opening output stream!";
        return 1;
      }
    }
    {
      google::protobuf::io::OstreamOutputStream zero_copy_output(output_stream);
      google::protobuf::TextFormat::Print(config, &zero_copy_output);
    }
    if (FLAGS_test_config != "") {
      ((fstream*) output_stream)->close();
      delete output_stream;
    }
  } else {
    cerr << "Not sure what you're trying to do; try " << argv[0]
         << " --help for usage information!";
    return 2;
  }
}

