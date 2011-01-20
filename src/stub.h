/**
 * stub.h - LaRPC Stub.
 * Copyright (C) 2010 Andrew Reusch <areusch@gmail.com>
 *
 */

#ifndef _STUB_H
#define _STUB_H

namespace larpc {

class Channel;

class Stub {
 public:
  Stub(const ServiceDescriptorProto& srv,
       Channel* channel);

  
  

#endif // _STUB_H


