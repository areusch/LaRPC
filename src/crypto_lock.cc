/**
 * crypto_lock.cc - OpenSSL Crypto Locking functions.
 * Copyright (C) 2010 Andrew Reusch <areusch@gmail.com>
 *
 */

#include "crypto_lock.h"
#include <set>
#include <boost/thread.hpp>
#include <boost/interprocess/sync/scoped_lock.hpp>
#include <glog/logging.h>
#include <openssl/crypto.h>


struct CRYPTO_dynlock_value {
  boost::shared_mutex mutex;
};

namespace larpc {

#define CRYPTO_MAX_STATIC_LOCKS      1000L

using ::boost::interprocess::scoped_lock;
using ::boost::shared_mutex;
using ::std::pair;
using ::std::set;

using ::CRYPTO_dynlock_value;

boost::once_flag services_init = BOOST_ONCE_INIT;

// Global locks
static shared_mutex** static_locks;

typedef set< ::boost::thread::id> IdSet;

static shared_mutex id_set_guard;
static IdSet id_set;

static void do_init_locking_services();

void crypto_init_locking_services() {
  call_once(services_init, &do_init_locking_services);
}

static void crypto_lock_function(int mode, shared_mutex* mutex) {
  if (mode & CRYPTO_LOCK) {
    if (mode & CRYPTO_READ) {
      mutex->lock();
    } else if (mode & CRYPTO_WRITE) {
      mutex->lock_upgrade();
      mutex->unlock_upgrade_and_lock();
    } else {
      CHECK(false) << "Invalid call on crypto locking function!";
    }
  } else if (mode & CRYPTO_UNLOCK) {
    mutex->unlock();
  } else {
    CHECK(false) << "Operation not specified!";
  }
}

/**
 * OpenSSL locking callback.
 */
static void crypto_static_lock_function(int mode, int n, const char* file, int line) {
  if (static_locks[n] == NULL)
    static_locks[n] = new shared_mutex;
  shared_mutex* mutex = static_locks[n];

  VLOG(1) << "Static " << std::string((mode & CRYPTO_WRITE) ? "write " : "") << std::string((mode & CRYPTO_UNLOCK) ? "un" : "") + "lock " << n << ": " << (void*) mutex;
  
  crypto_lock_function(mode, mutex);
}

static void crypto_id_function(CRYPTO_THREADID* tid) {
  ::boost::thread::id thread_id = ::boost::this_thread::get_id();
  
  scoped_lock<shared_mutex> lock(id_set_guard);
  pair<IdSet::iterator, bool> it = id_set.insert(thread_id);
  
  VLOG_IF(1, it.second) << "Inserted id " << (void*) &(*(it.first));
  
  CRYPTO_THREADID_set_pointer(tid, (void*) &(*(it.first)));
}

static struct CRYPTO_dynlock_value* dynlock_create_function(const char* file, int line) {
  struct CRYPTO_dynlock_value* lock = new struct CRYPTO_dynlock_value;
  VLOG(2) << "Dynlock create " << (void*) lock;
  return lock;
}

static void dynlock_destroy_function(struct CRYPTO_dynlock_value* lock, 
                                     const char* file, 
                                     int line) {
  VLOG(2) << "Dynlock destroy " << (void*) lock;
  delete lock;
}

static void dynlock_lock_function(int mode, 
                                  struct CRYPTO_dynlock_value* lock, 
                                  const char* file, 
                                  int line) {
  crypto_lock_function(mode, &lock->mutex);
}

void do_init_locking_services() {
  int num_static_locks = CRYPTO_num_locks();
  VLOG(2) << "Setting up " << num_static_locks << " locks...";
  CHECK(num_static_locks <= CRYPTO_MAX_STATIC_LOCKS) << 
    "OpenSSL requires too many static locks (" << num_static_locks << ")";
  static_locks = new shared_mutex*[num_static_locks];
  for (int i = 0; i < num_static_locks; ++i)
    static_locks[i] = NULL;

  CRYPTO_set_locking_callback(&crypto_static_lock_function);
  CRYPTO_THREADID_set_callback(&crypto_id_function);

  // Dynlocks
  CRYPTO_set_dynlock_create_callback(&dynlock_create_function);
  CRYPTO_set_dynlock_lock_callback(&dynlock_lock_function);
  CRYPTO_set_dynlock_destroy_callback(&dynlock_destroy_function);
}

} // namespace larpc
