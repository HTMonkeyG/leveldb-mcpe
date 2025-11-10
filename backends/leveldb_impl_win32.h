// Copyright (c) 2011 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.

#ifndef STORAGE_LEVELDB_IMPL_WIN32_H_
#define STORAGE_LEVELDB_IMPL_WIN32_H_

#include <stdio.h>
#include <string>
#include <mutex>
#include <stdint.h>
#include <cassert>
#include <condition_variable>

#include "leveldb.h"
#include "leveldb_backend.h"
#include "leveldb_config.h"

namespace leveldb {

// ----------------------------------------------------------------------------
// - util/win_logger.h
//
// Logger implementation for Windows
// ----------------------------------------------------------------------------

class WinLogger: public Logger {
private:
  FILE *file_;
public:
  explicit WinLogger(FILE *f): file_(f) {
    assert(file_);
  }
  virtual ~WinLogger() {
    fclose(file_);
  }
  virtual void Logv(const char *format, va_list ap);

};

// ----------------------------------------------------------------------------
// - port/port_win.h
// ----------------------------------------------------------------------------

namespace port {

// Windows is little endian (for now :p)
static const bool kLittleEndian = true;

class CondVar;

class Mutex {
public:
  Mutex() {

  }

  void Lock() {
    mutex.lock();
  }
  void Unlock() {
    mutex.unlock();
  }

  void AssertHeld() {
    //TODO
  }

private:
  friend class CondVar;

  std::mutex mutex;
};

// Thinly wraps std::condition_variable.
class CondVar {
public:
  explicit CondVar(Mutex *mu): mu_(mu) {
    assert(mu != nullptr);
  }
  ~CondVar() = default;

  CondVar(const CondVar &) = delete;
  CondVar &operator=(const CondVar &) = delete;

  void Wait() {
    std::unique_lock<std::mutex> lock(mu_->mutex, std::adopt_lock);
    cv_.wait(lock);
    lock.release();
  }
  void Signal() {
    cv_.notify_one();
  }
  void SignalAll() {
    cv_.notify_all();
  }
private:
  std::condition_variable cv_;
  Mutex *const mu_;
};

// Storage for a lock-free pointer
class AtomicPointer {
private:
  void *rep_;
public:
  AtomicPointer(): rep_(nullptr) { }
  explicit AtomicPointer(void *v);
  void *Acquire_Load() const;

  void Release_Store(void *v);

  void *NoBarrier_Load() const;

  void NoBarrier_Store(void *v);
};

// Thread-safe initialization.
// Used as follows:
//      static port::OnceType init_control = LEVELDB_ONCE_INIT;
//      static void Initializer() { ... do something ...; }
//      ...
//      port::InitOnce(&init_control, &Initializer);
typedef intptr_t OnceType;
#define LEVELDB_ONCE_INIT 0
inline void InitOnce(port::OnceType *, void(*initializer)()) {
  initializer();
}

inline bool GetHeapProfile(void(*func)(void *, const char *, int), void *arg) {
  return false;
}

uint32_t AcceleratedCRC32C(uint32_t crc, const char *buf, size_t size);

} // namespace port

} // namespace leveldb

#endif // STORAGE_LEVELDB_UTIL_WIN_LOGGER_H_
