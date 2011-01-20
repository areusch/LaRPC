/**
 * connect_test.cc - Connection Unit Test
 * Copyright (C) 2010 Andrew Reusch <areusch@gmail.com>
 *
 */

#include "framework.h"

/** TestConfig: --num_principles_per_node=2 --num_nodes=2 */

class ConnectTest : public larpc::test::NWayTest<2>
{};

TEST_F(ConnectTest, InstancesStartOK) {
  LOG(INFO) << "well i guess it's okay...";
}
