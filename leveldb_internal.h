// Copyright (c) 2011 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.

#pragma once

#include <stdint.h>
#include <assert.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <stddef.h>
#include <string>
#include <vector>
#include <mutex>
#include <memory>
#include <unordered_map>
#include <deque>
#include <set>

#include "leveldb_thread_annotations.h"
#include "leveldb_backend.h"
#include "leveldb_config.h"
#include "leveldb.h"

namespace leveldb {

// Update Makefile if you change these
static const int kMajorVersion = 1;
static const int kMinorVersion = 20;

// Type declarations.
typedef uint64_t SequenceNumber;

struct FileMetaData;
struct BlockContents;

namespace log {
  class Writer;
}

class LEVELDB_DLLX BlockBuilder;
class LEVELDB_DLLX BlockHandle;
class LEVELDB_DLLX Cache;
class LEVELDB_DLLX Comparator;
class LEVELDB_DLLX Compressor;
class LEVELDB_DLLX DecompressAllocator;
class LEVELDB_DLLX Env;
class LEVELDB_DLLX FileLock;
class LEVELDB_DLLX FilterPolicy;
class LEVELDB_DLLX Footer;
class LEVELDB_DLLX Iterator;
class LEVELDB_DLLX Logger;
class LEVELDB_DLLX RandomAccessFile;
class LEVELDB_DLLX SequentialFile;
class LEVELDB_DLLX Slice;
class LEVELDB_DLLX Status;
class LEVELDB_DLLX TableBuilder;
class LEVELDB_DLLX TableCache;
class LEVELDB_DLLX WriteBatch;
class LEVELDB_DLLX WritableFile;

class Compaction;
class DBImpl;
class InternalKeyComparator;
class TableCache;
class MemTable;
class Version;
class VersionEdit;
class VersionSet;
class SnapshotList;

template<typename Key, class Comparator>
class SkipList;

// ----------------------------------------------------------------------------
// - util/Filepath.h
// ----------------------------------------------------------------------------

namespace port {

#if defined(_MSC_VER)
// std::strings won't work for windows as all their STL/Win32 APIs assume char* are pure ASCII
// "luckily", there is an unofficial parameter for iostream that takes a wide character Unicode string
typedef std::wstring filepath;
typedef wchar_t filepath_char;
#define _FILE_STR(str) L ## str
#else
typedef std::string filepath;
typedef char filepath_char;
#define _FILE_STR(str) str
#endif


inline filepath toFilePath(const std::string &string) {
#if defined(_MSC_VER)
  std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;
  return std::move(converter.from_bytes(string));
#else
  return std::move(string);
#endif
}

#if defined(_MSC_VER)
inline FILE *fopen_mb(const filepath_char *filename, const filepath_char *mode) {
  FILE *file = nullptr;

  errno_t error = _wfopen_s(&file, filename, mode);
  _set_errno(error);

  return file;
}

// this function will silently allocate memory on windows to convert char* to wchar_t*
inline FILE *fopen_mb(const char *const filename, const filepath_char *mode) {
  filepath path = toFilePath(filename);

  return port::fopen_mb(path.c_str(), mode);
}
#else
inline FILE *fopen_mb(const filepath_char *filename, const filepath_char *mode) {
  return ::fopen(filename, mode);
}
#endif
}

// ----------------------------------------------------------------------------
// - utils/arena.h
// ----------------------------------------------------------------------------

class Arena {
public:
  Arena();
  ~Arena();

  // Return a pointer to a newly allocated memory block of "bytes" bytes.
  char *Allocate(size_t bytes);

  // Allocate memory with the normal alignment guarantees provided by malloc
  char *AllocateAligned(size_t bytes);

  // Returns an estimate of the total memory usage of data allocated
  // by the arena.
  size_t MemoryUsage() const {
    return reinterpret_cast<uintptr_t>(memory_usage_.NoBarrier_Load());
  }

private:
  char *AllocateFallback(size_t bytes);
  char *AllocateNewBlock(size_t block_bytes);

  // Allocation state
  char *alloc_ptr_;
  size_t alloc_bytes_remaining_;

  // Array of new[] allocated memory blocks
  std::vector<char *> blocks_;

  // Total memory usage of the arena.
  port::AtomicPointer memory_usage_;

  // No copying allowed
  Arena(const Arena &);
  void operator=(const Arena &);
};

inline char *Arena::Allocate(size_t bytes) {
  // The semantics of what to return are a bit messy if we allow
  // 0-byte allocations, so we disallow them here (we don't need
  // them for our internal use).
  assert(bytes > 0);
  if (bytes <= alloc_bytes_remaining_) {
    char *result = alloc_ptr_;
    alloc_ptr_ += bytes;
    alloc_bytes_remaining_ -= bytes;
    return result;
  }
  return AllocateFallback(bytes);
}

// ----------------------------------------------------------------------------
// - utils/coding.h
//
// Endian-neutral encoding:
// * Fixed-length numbers are encoded with least-significant byte first
// * In addition we support variable length "varint" encoding
// * Strings are encoded prefixed by their length in varint format
// ----------------------------------------------------------------------------

// Standard Put... routines append to a string
extern void PutFixed32(std::string *dst, uint32_t value);
extern void PutFixed64(std::string *dst, uint64_t value);
extern void PutVarint32(std::string *dst, uint32_t value);
extern void PutVarint64(std::string *dst, uint64_t value);
extern void PutLengthPrefixedSlice(std::string *dst, const Slice &value);

// Standard Get... routines parse a value from the beginning of a Slice
// and advance the slice past the parsed value.
extern bool GetVarint32(Slice *input, uint32_t *value);
extern bool GetVarint64(Slice *input, uint64_t *value);
extern bool GetLengthPrefixedSlice(Slice *input, Slice *result);

// Pointer-based variants of GetVarint...  These either store a value
// in *v and return a pointer just past the parsed value, or return
// NULL on error.  These routines only look at bytes in the range
// [p..limit-1]
extern const char *GetVarint32Ptr(const char *p, const char *limit, uint32_t *v);
extern const char *GetVarint64Ptr(const char *p, const char *limit, uint64_t *v);

// Returns the length of the varint32 or varint64 encoding of "v"
extern int VarintLength(uint64_t v);

// Lower-level versions of Put... that write directly into a character buffer
// REQUIRES: dst has enough space for the value being written
extern void EncodeFixed32(char *dst, uint32_t value);
extern void EncodeFixed64(char *dst, uint64_t value);

// Lower-level versions of Put... that write directly into a character buffer
// and return a pointer just past the last byte written.
// REQUIRES: dst has enough space for the value being written
extern char *EncodeVarint32(char *dst, uint32_t value);
extern char *EncodeVarint64(char *dst, uint64_t value);

// Lower-level versions of Get... that read directly from a character buffer
// without any bounds checking.

inline uint32_t DecodeFixed32(const char *ptr) {
  if (port::kLittleEndian) {
    // Load the raw bytes
    uint32_t result;
    memcpy(&result, ptr, sizeof(result));  // gcc optimizes this to a plain load
    return result;
  } else {
    return ((static_cast<uint32_t>(static_cast<unsigned char>(ptr[0])))
      | (static_cast<uint32_t>(static_cast<unsigned char>(ptr[1])) << 8)
      | (static_cast<uint32_t>(static_cast<unsigned char>(ptr[2])) << 16)
      | (static_cast<uint32_t>(static_cast<unsigned char>(ptr[3])) << 24));
  }
}

inline uint64_t DecodeFixed64(const char *ptr) {
  if (port::kLittleEndian) {
    // Load the raw bytes
    uint64_t result;
    memcpy(&result, ptr, sizeof(result));  // gcc optimizes this to a plain load
    return result;
  } else {
    uint64_t lo = DecodeFixed32(ptr);
    uint64_t hi = DecodeFixed32(ptr + 4);
    return (hi << 32) | lo;
  }
}

// Internal routine for use by fallback path of GetVarint32Ptr
extern const char *GetVarint32PtrFallback(const char *p,
  const char *limit,
  uint32_t *value);
inline const char *GetVarint32Ptr(const char *p,
  const char *limit,
  uint32_t *value) {
  if (p < limit) {
    uint32_t result = *(reinterpret_cast<const unsigned char *>(p));
    if ((result & 128) == 0) {
      *value = result;
      return p + 1;
    }
  }
  return GetVarint32PtrFallback(p, limit, value);
}

// ----------------------------------------------------------------------------
// - utils/crc32c.h
// ----------------------------------------------------------------------------

namespace crc32c {

// Return the crc32c of concat(A, data[0,n-1]) where init_crc is the
// crc32c of some string A.  Extend() is often used to maintain the
// crc32c of a stream of data.
extern uint32_t Extend(uint32_t init_crc, const char *data, size_t n);

// Return the crc32c of data[0,n-1]
inline uint32_t Value(const char *data, size_t n) {
  return Extend(0, data, n);
}

static const uint32_t kMaskDelta = 0xa282ead8ul;

// Return a masked representation of crc.
//
// Motivation: it is problematic to compute the CRC of a string that
// contains embedded CRCs.  Therefore we recommend that CRCs stored
// somewhere (e.g., in files) should be masked before being stored.
inline uint32_t Mask(uint32_t crc) {
  // Rotate right by 15 bits and add a constant.
  return ((crc >> 15) | (crc << 17)) + kMaskDelta;
}

// Return the crc whose masked representation is masked_crc.
inline uint32_t Unmask(uint32_t masked_crc) {
  uint32_t rot = masked_crc - kMaskDelta;
  return ((rot >> 17) | (rot << 15));
}

} // namespace crc32c

// ----------------------------------------------------------------------------
// - utils/hash.h
// ----------------------------------------------------------------------------

extern uint32_t Hash(const char *data, size_t n, uint32_t seed);

// ----------------------------------------------------------------------------
// - utils/histogram.h
// ----------------------------------------------------------------------------

class Histogram {
public:
  Histogram() { }
  ~Histogram() { }

  void Clear();
  void Add(double value);
  void Merge(const Histogram &other);

  std::string ToString() const;

private:
  double min_;
  double max_;
  double num_;
  double sum_;
  double sum_squares_;

  enum {
    kNumBuckets = 154
  };
  static const double kBucketLimit[kNumBuckets];
  double buckets_[kNumBuckets];

  double Median() const;
  double Percentile(double p) const;
  double Average() const;
  double StandardDeviation() const;
};

// ----------------------------------------------------------------------------
// - utils/logging.h
//
// Must not be included from any .h files to avoid polluting the namespace
// with macros.
// ----------------------------------------------------------------------------

// Append a human-readable printout of "num" to *str
extern void AppendNumberTo(std::string *str, uint64_t num);

// Append a human-readable printout of "value" to *str.
// Escapes any non-printable characters found in "value".
extern void AppendEscapedStringTo(std::string *str, const Slice &value);

// Return a human-readable printout of "num"
extern std::string NumberToString(uint64_t num);

// Return a human-readable version of "value".
// Escapes any non-printable characters found in "value".
extern std::string EscapeString(const Slice &value);

// Parse a human-readable number from "*in" into *value.  On success,
// advances "*in" past the consumed number and sets "*val" to the
// numeric value.  Otherwise, returns false and leaves *in in an
// unspecified state.
extern bool ConsumeDecimalNumber(Slice *in, uint64_t *val);

// ----------------------------------------------------------------------------
// - utils/mutexlock.h
// ----------------------------------------------------------------------------

// Helper class that locks a mutex on construction and unlocks the mutex when
// the destructor of the MutexLock object is invoked.
//
// Typical usage:
//
//   void MyClass::MyMethod() {
//     MutexLock l(&mu_);       // mu_ is an instance variable
//     ... some complex code, possibly with multiple return paths ...
//   }

class SCOPED_LOCKABLE MutexLock {
public:
  explicit MutexLock(port::Mutex *mu) EXCLUSIVE_LOCK_FUNCTION(mu)
    : mu_(mu) {
    this->mu_->Lock();
  }
  ~MutexLock() UNLOCK_FUNCTION() {
    this->mu_->Unlock();
  }

private:
  port::Mutex *const mu_;
  // No copying allowed
  MutexLock(const MutexLock &);
  void operator=(const MutexLock &);
};

// ----------------------------------------------------------------------------
// - utils/random.h
// ----------------------------------------------------------------------------

// A very simple random number generator.  Not especially good at
// generating truly random bits, but good enough for our needs in this
// package.
class Random {
private:
  uint32_t seed_;
public:
  explicit Random(uint32_t s): seed_(s & 0x7fffffffu) {
    // Avoid bad seeds.
    if (seed_ == 0 || seed_ == 2147483647L) {
      seed_ = 1;
    }
  }
  uint32_t Next() {
    static const uint32_t M = 2147483647L;   // 2^31-1
    static const uint64_t A = 16807;  // bits 14, 8, 7, 5, 2, 1, 0
    // We are computing
    //       seed_ = (seed_ * A) % M,    where M = 2^31-1
    //
    // seed_ must not be zero or M, or else all subsequent computed values
    // will be zero or M respectively.  For all other values, seed_ will end
    // up cycling through every number in [1,M-1]
    uint64_t product = seed_ * A;

    // Compute (product % M) using the fact that ((x << 31) % M) == x.
    seed_ = static_cast<uint32_t>((product >> 31) + (product & M));
    // The first reduction may overflow by 1 bit, so we may need to
    // repeat.  mod == M is not possible; using > allows the faster
    // sign-bit-based test.
    if (seed_ > M) {
      seed_ -= M;
    }
    return seed_;
  }
  // Returns a uniformly distributed value in the range [0..n-1]
  // REQUIRES: n > 0
  uint32_t Uniform(int n) {
    return Next() % n;
  }

  // Randomly returns true ~"1/n" of the time, and false otherwise.
  // REQUIRES: n > 0
  bool OneIn(int n) {
    return (Next() % n) == 0;
  }

  // Skewed: pick "base" uniformly from range [0,max_log] and then
  // return "base" random bits.  The effect is to pick a number in the
  // range [0,2^max_log-1] with exponential bias towards smaller numbers.
  uint32_t Skewed(int max_log) {
    return Uniform(1 << Uniform(max_log + 1));
  }
};

// ----------------------------------------------------------------------------
// - cache.h
// 
// A Cache is an interface that maps keys to values.  It has internal
// synchronization and may be safely accessed concurrently from
// multiple threads.  It may automatically evict entries to make room
// for new entries.  Values have a specified charge against the cache
// capacity.  For example, a cache where the values are variable
// length strings, may use the length of the string as the charge for
// the string.
//
// A builtin cache implementation with a least-recently-used eviction
// policy is provided.  Clients may use their own implementations if
// they want something more sophisticated (like scan-resistance, a
// custom eviction policy, variable cache sizing, etc.)
//
// Create a new cache with a fixed size capacity.  This implementation
// of Cache uses a least-recently-used eviction policy.
// ----------------------------------------------------------------------------

extern LEVELDB_DLLX Cache *NewLRUCache(size_t capacity);

class LEVELDB_DLLX Cache {
public:

  Cache() { }

  // Destroys all existing entries by calling the "deleter"
  // function that was passed to the constructor.
  virtual ~Cache();

  // Opaque handle to an entry stored in the cache.
  struct LEVELDB_DLLX Handle { };

  // Insert a mapping from key->value into the cache and assign it
  // the specified charge against the total cache capacity.
  //
  // Returns a handle that corresponds to the mapping.  The caller
  // must call this->Release(handle) when the returned mapping is no
  // longer needed.
  //
  // When the inserted entry is no longer needed, the key and
  // value will be passed to "deleter".
  virtual Handle *Insert(
    const Slice &key,
    void *value,
    size_t charge,
    void (*deleter)(const Slice &key, void *value)
  ) = 0;

  // If the cache has no mapping for "key", returns NULL.
  //
  // Else return a handle that corresponds to the mapping.  The caller
  // must call this->Release(handle) when the returned mapping is no
  // longer needed.
  virtual Handle *Lookup(
    const Slice &key
  ) = 0;

  // Release a mapping returned by a previous Lookup().
  // REQUIRES: handle must not have been released yet.
  // REQUIRES: handle must have been returned by a method on *this.
  virtual void Release(Handle *handle) = 0;

  // Return the value encapsulated in a handle returned by a
  // successful Lookup().
  // REQUIRES: handle must not have been released yet.
  // REQUIRES: handle must have been returned by a method on *this.
  virtual void *Value(Handle *handle) = 0;

  // If the cache contains entry for key, erase it.  Note that the
  // underlying entry will be kept around until all existing handles
  // to it have been released.
  virtual void Erase(const Slice &key) = 0;

  // Return a new numeric id.  May be used by multiple clients who are
  // sharing the same cache to partition the key space.  Typically the
  // client will allocate a new id at startup and prepend the id to
  // its cache keys.
  virtual uint64_t NewId() = 0;

  // Remove all cache entries that are not actively in use.  Memory-constrained
  // applications may wish to call this method to reduce memory usage.
  // Default implementation of Prune() does nothing.  Subclasses are strongly
  // encouraged to override the default implementation.  A future release of
  // leveldb may change Prune() to a pure abstract method.
  virtual void Prune() { }

  // Return an estimate of the combined charges of all elements stored in the
  // cache.
  virtual size_t TotalCharge() const = 0;

private:
  void LRU_Remove(Handle *e);
  void LRU_Append(Handle *e);
  void Unref(Handle *e);

  struct LEVELDB_DLLX Rep;
  Rep *rep_;

  // No copying allowed
  Cache(const Cache &);
  void operator=(const Cache &);
};

// ----------------------------------------------------------------------------
// - compressor.h
// ----------------------------------------------------------------------------

class LEVELDB_DLLX Compressor {
public:

  uint64_t inputBytes = 0, compressedBytes = 0;

  // An ID that has to be unique across the whole system
  const char uniqueCompressionID;

  virtual ~Compressor() { }

  Compressor(
    char uniqueCompressionID
  )
    : uniqueCompressionID(uniqueCompressionID) { }

  double getAverageCompression() const {
    return inputBytes ? ((double)compressedBytes / (double)inputBytes) : 0;
  }

  void resetAverageCompressionStats() {
    inputBytes = compressedBytes = 0;
  }

  void compress(
    const char *input,
    size_t length,
    std::string &output
  ) {
    compressImpl(input, length, output);

    inputBytes += length;
    compressedBytes += output.length();
  }

  void compress(const std::string &in, std::string &out) {
    compress(in.data(), in.length(), out);
  }

  virtual void compressImpl(
    const char *input,
    size_t length,
    std::string &output
  ) const = 0;

  virtual bool decompress(
    const char *input,
    size_t length,
    std::string &output
  ) const = 0;

  bool decompress(
    const std::string &input,
    std::string &output
  ) const {
    return decompress(input.data(), input.length(), output);
  }

protected:
private:
};

// ----------------------------------------------------------------------------
// - write_batch.h
//
// WriteBatch holds a collection of updates to apply atomically to a DB.
//
// The updates are applied in the order in which they are added
// to the WriteBatch.  For example, the value of "key" will be "v3"
// after the following batch is written:
//
//    batch.Put("key", "v1");
//    batch.Delete("key");
//    batch.Put("key", "v2");
//    batch.Put("key", "v3");
//
// Multiple threads can invoke const methods on a WriteBatch without
// external synchronization, but if any of the threads may call a
// non-const method, all threads accessing the same WriteBatch must use
// external synchronization.
// ----------------------------------------------------------------------------

class LEVELDB_DLLX WriteBatch {
public:

  WriteBatch();
  ~WriteBatch();

  // Store the mapping "key->value" in the database.
  void Put(
    const Slice &key,
    const Slice &value);

  // If the database contains a mapping for "key", erase it.  Else do nothing.
  void Delete(
    const Slice &key
  );

  // Clear all updates buffered in this batch.
  void Clear();

  // The size of the database changes caused by this batch.
  //
  // This number is tied to implementation details, and may change across
  // releases. It is intended for LevelDB usage metrics.
  size_t ApproximateSize();

  // Support for iterating over the contents of a batch.
  class LEVELDB_DLLX Handler {
  public:
    virtual ~Handler();
    virtual void Put(const Slice &key, const Slice &value) = 0;
    virtual void Delete(const Slice &key) = 0;
  };
  Status Iterate(Handler *handler) const;

private:
  friend class WriteBatchInternal;

  std::string rep_;  // See comment in write_batch.cc for the format of rep_

  // Intentionally copyable
};

// ----------------------------------------------------------------------------
// - table.h
// ----------------------------------------------------------------------------

// A Table is a sorted map from strings to strings.  Tables are
// immutable and persistent.  A Table may be safely accessed from
// multiple threads without external synchronization.
class LEVELDB_DLLX Table {
public:
  // Attempt to open the table that is stored in bytes [0..file_size)
  // of "file", and read the metadata entries necessary to allow
  // retrieving data from the table.
  //
  // If successful, returns ok and sets "*table" to the newly opened
  // table.  The client should delete "*table" when no longer needed.
  // If there was an error while initializing the table, sets "*table"
  // to NULL and returns a non-ok status.  Does not take ownership of
  // "*source", but the client must ensure that "source" remains live
  // for the duration of the returned table's lifetime.
  //
  // *file must remain live while this Table is in use.
  static Status Open(
    const Options &options,
    RandomAccessFile *file,
    uint64_t file_size,
    Table **table);

  ~Table();

  // Returns a new iterator over the table contents.
  // The result of NewIterator() is initially invalid (caller must
  // call one of the Seek methods on the iterator before using it).
  Iterator *NewIterator(const ReadOptions &) const;

  // Given a key, return an approximate byte offset in the file where
  // the data for that key begins (or would begin if the key were
  // present in the file).  The returned value is in terms of file
  // bytes, and so includes effects like compression of the underlying data.
  // E.g., the approximate offset of the last key in the table will
  // be close to the file length.
  uint64_t ApproximateOffsetOf(const Slice &key) const;

private:
  struct LEVELDB_DLLX Rep;
  Rep *rep_;

  explicit Table(Rep *rep) {
    rep_ = rep;
  }
  static Iterator *BlockReader(void *, const ReadOptions &, const Slice &);

  // Calls (*handle_result)(arg, ...) with the entry found after a call
  // to Seek(key).  May not make such a call if filter policy says
  // that key is not present.
  friend class LEVELDB_DLLX TableCache;
  Status InternalGet(
    const ReadOptions &, const Slice &key,
    void *arg,
    void (*handle_result)(void *arg, const Slice &k, const Slice &v));

  void ReadMeta(const Footer &footer);
  void ReadFilter(const Slice &filter_handle_value);

  // No copying allowed
  Table(const Table &);
  void operator=(const Table &);
};

// ----------------------------------------------------------------------------
// - table_builder.h
// 
// TableBuilder provides the interface used to build a Table
// (an immutable and sorted map from keys to values).
//
// Multiple threads can invoke const methods on a TableBuilder without
// external synchronization, but if any of the threads may call a
// non-const method, all threads accessing the same TableBuilder must use
// external synchronization.
// ----------------------------------------------------------------------------

class LEVELDB_DLLX TableBuilder {
public:
  // Create a builder that will store the contents of the table it is
  // building in *file.  Does not close the file.  It is up to the
  // caller to close the file after calling Finish().
  TableBuilder(const Options &options, WritableFile *file);

  // REQUIRES: Either Finish() or Abandon() has been called.
  ~TableBuilder();

  // Change the options used by this builder.  Note: only some of the
  // option fields can be changed after construction.  If a field is
  // not allowed to change dynamically and its value in the structure
  // passed to the constructor is different from its value in the
  // structure passed to this method, this method will return an error
  // without changing any fields.
  Status ChangeOptions(const Options &options);

  // Add key,value to the table being constructed.
  // REQUIRES: key is after any previously added key according to comparator.
  // REQUIRES: Finish(), Abandon() have not been called
  void Add(const Slice &key, const Slice &value);

  // Advanced operation: flush any buffered key/value pairs to file.
  // Can be used to ensure that two adjacent entries never live in
  // the same data block.  Most clients should not need to use this method.
  // REQUIRES: Finish(), Abandon() have not been called
  void Flush();

  // Return non-ok iff some error has been detected.
  Status status() const;

  // Finish building the table.  Stops using the file passed to the
  // constructor after this function returns.
  // REQUIRES: Finish(), Abandon() have not been called
  Status Finish();

  // Indicate that the contents of this builder should be abandoned.  Stops
  // using the file passed to the constructor after this function returns.
  // If the caller is not going to call Finish(), it must call Abandon()
  // before destroying this builder.
  // REQUIRES: Finish(), Abandon() have not been called
  void Abandon();

  // Number of calls to Add() so far.
  uint64_t NumEntries() const;

  // Size of the file generated so far.  If invoked after a successful
  // Finish() call, returns the size of the final generated file.
  uint64_t FileSize() const;

private:
  bool ok() const {
    return status().ok();
  }
  void WriteBlock(BlockBuilder *block, BlockHandle *handle);
  void WriteRawBlock(const Slice &data, Compressor *compressor, BlockHandle *handle);

  struct LEVELDB_DLLX Rep;
  Rep *rep_;

  // No copying allowed
  TableBuilder(const TableBuilder &);
  void operator=(const TableBuilder &);
};

// ----------------------------------------------------------------------------
// - filter_policy.h
//
// A database can be configured with a custom FilterPolicy object.
// This object is responsible for creating a small filter from a set
// of keys.  These filters are stored in leveldb and are consulted
// automatically by leveldb to decide whether or not to read some
// information from disk. In many cases, a filter can cut down the
// number of disk seeks form a handful to a single disk seek per
// DB::Get() call.
//
// Most people will want to use the builtin bloom filter support (see
// NewBloomFilterPolicy() below).
// ----------------------------------------------------------------------------

class LEVELDB_DLLX FilterPolicy {
public:
  virtual ~FilterPolicy();

  // Return the name of this policy.  Note that if the filter encoding
  // changes in an incompatible way, the name returned by this method
  // must be changed.  Otherwise, old incompatible filters may be
  // passed to methods of this type.
  virtual const char *Name() const = 0;

  // keys[0,n-1] contains a list of keys (potentially with duplicates)
  // that are ordered according to the user supplied comparator.
  // Append a filter that summarizes keys[0,n-1] to *dst.
  //
  // Warning: do not change the initial contents of *dst.  Instead,
  // append the newly constructed filter to *dst.
  virtual void CreateFilter(const Slice *keys, int n, std::string *dst)
    const = 0;

  // "filter" contains the data appended by a preceding call to
  // CreateFilter() on this class.  This method must return true if
  // the key was in the list of keys passed to CreateFilter().
  // This method may return true or false if the key was not on the
  // list, but it should aim to return false with a high probability.
  virtual bool KeyMayMatch(const Slice &key, const Slice &filter) const = 0;
};

// Return a new filter policy that uses a bloom filter with approximately
// the specified number of bits per key.  A good value for bits_per_key
// is 10, which yields a filter with ~ 1% false positive rate.
//
// Callers must delete the result after any database that is using the
// result has been closed.
//
// Note: if you are using a custom comparator that ignores some parts
// of the keys being compared, you must not use NewBloomFilterPolicy()
// and must provide your own FilterPolicy that also ignores the
// corresponding parts of the keys.  For example, if the comparator
// ignores trailing spaces, it would be incorrect to use a
// FilterPolicy (like NewBloomFilterPolicy) that does not ignore
// trailing spaces in keys.
extern LEVELDB_DLLX const FilterPolicy *NewBloomFilterPolicy(int bits_per_key);

// ----------------------------------------------------------------------------
// - env.h
//
// An Env is an interface used by the leveldb implementation to access
// operating system functionality like the filesystem etc.  Callers
// may wish to provide a custom Env object when opening a database to
// get fine gain control; e.g., to rate limit file system operations.
//
// All Env implementations are safe for concurrent access from
// multiple threads without any external synchronization.
// ----------------------------------------------------------------------------

class LEVELDB_DLLX Env {
public:
  Env() { }
  virtual ~Env();

  // Return a default environment suitable for the current operating
  // system.  Sophisticated users may wish to provide their own Env
  // implementation instead of relying on this default environment.
  //
  // The result of Default() belongs to leveldb and must never be deleted.
  static Env *Default();

  // Create a brand new sequentially-readable file with the specified name.
  // On success, stores a pointer to the new file in *result and returns OK.
  // On failure stores NULL in *result and returns non-OK.  If the file does
  // not exist, returns a non-OK status.  Implementations should return a
  // NotFound status when the file does not exist.
  //
  // The returned file will only be accessed by one thread at a time.
  virtual Status NewSequentialFile(
    const std::string &fname,
    SequentialFile **result
  ) = 0;

  // Create a brand new random access read-only file with the
  // specified name.  On success, stores a pointer to the new file in
  // *result and returns OK.  On failure stores NULL in *result and
  // returns non-OK.  If the file does not exist, returns a non-OK
  // status.  Implementations should return a NotFound status when the file does
  // not exist.
  //
  // The returned file may be concurrently accessed by multiple threads.
  virtual Status NewRandomAccessFile(
    const std::string &fname,
    RandomAccessFile **result
  ) = 0;

  // Create an object that writes to a new file with the specified
  // name.  Deletes any existing file with the same name and creates a
  // new file.  On success, stores a pointer to the new file in
  // *result and returns OK.  On failure stores NULL in *result and
  // returns non-OK.
  //
  // The returned file will only be accessed by one thread at a time.
  virtual Status NewWritableFile(
    const std::string &fname,
    WritableFile **result
  ) = 0;

  // Create an object that either appends to an existing file, or
  // writes to a new file (if the file does not exist to begin with).
  // On success, stores a pointer to the new file in *result and
  // returns OK.  On failure stores NULL in *result and returns
  // non-OK.
  //
  // The returned file will only be accessed by one thread at a time.
  //
  // May return an IsNotSupportedError error if this Env does
  // not allow appending to an existing file.  Users of Env (including
  // the leveldb implementation) must be prepared to deal with
  // an Env that does not support appending.
  virtual Status NewAppendableFile(
    const std::string &fname,
    WritableFile **result
  );

  // Returns true iff the named file exists.
  virtual bool FileExists(
    const std::string &fname
  ) = 0;

  // Store in *result the names of the children of the specified directory.
  // The names are relative to "dir".
  // Original contents of *results are dropped.
  virtual Status GetChildren(
    const std::string &dir,
    std::vector<std::string> *result
  ) = 0;

  // Delete the named file.
  virtual Status DeleteFile(
    const std::string &fname
  ) = 0;

  // Create the specified directory.
  virtual Status CreateDir(
    const std::string &dirname
  ) = 0;

  // Delete the specified directory.
  virtual Status DeleteDir(
    const std::string &dirname
  ) = 0;

  // Store the size of fname in *file_size.
  virtual Status GetFileSize(
    const std::string &fname,
    uint64_t *file_size
  ) = 0;

  // Rename file src to target.
  virtual Status RenameFile(
    const std::string &src,
    const std::string &target
  ) = 0;

  // Lock the specified file.  Used to prevent concurrent access to
  // the same db by multiple processes.  On failure, stores NULL in
  // *lock and returns non-OK.
  //
  // On success, stores a pointer to the object that represents the
  // acquired lock in *lock and returns OK.  The caller should call
  // UnlockFile(*lock) to release the lock.  If the process exits,
  // the lock will be automatically released.
  //
  // If somebody else already holds the lock, finishes immediately
  // with a failure.  I.e., this call does not wait for existing locks
  // to go away.
  //
  // May create the named file if it does not already exist.
  virtual Status LockFile(
    const std::string &fname,
    FileLock **lock
  ) = 0;

  // Release the lock acquired by a previous successful call to LockFile.
  // REQUIRES: lock was returned by a successful LockFile() call
  // REQUIRES: lock has not already been unlocked.
  virtual Status UnlockFile(
    FileLock *lock
  ) = 0;

  // Arrange to run "(*function)(arg)" once in a background thread.
  //
  // "function" may run in an unspecified thread.  Multiple functions
  // added to the same Env may run concurrently in different threads.
  // I.e., the caller may not assume that background work items are
  // serialized.
  virtual void Schedule(
    void (*function)(void *arg),
    void *arg
  ) = 0;

  // Start a new thread, invoking "function(arg)" within the new thread.
  // When "function(arg)" returns, the thread will be destroyed.
  virtual void StartThread(
    void (*function)(void *arg),
    void *arg
  ) = 0;

  // *path is set to a temporary directory that can be used for testing. It may
  // or many not have just been created. The directory may or may not differ
  // between runs of the same process, but subsequent calls will return the
  // same directory.
  virtual Status GetTestDirectory(
    std::string *path
  ) = 0;

  // Create and return a log file for storing informational messages.
  virtual Status NewLogger(
    const std::string &fname,
    Logger **result
  ) = 0;

  // Returns the number of micro-seconds since some fixed point in time. Only
  // useful for computing deltas of time.
  virtual uint64_t NowMicros() = 0;

  // Sleep/delay the thread for the prescribed number of micro-seconds.
  virtual void SleepForMicroseconds(
    int micros
  ) = 0;

private:
  // No copying allowed
  Env(const Env &);
  void operator=(const Env &);
};

// A file abstraction for reading sequentially through a file
class LEVELDB_DLLX SequentialFile {
public:
  SequentialFile() { }
  virtual ~SequentialFile();

  // Read up to "n" bytes from the file.  "scratch[0..n-1]" may be
  // written by this routine.  Sets "*result" to the data that was
  // read (including if fewer than "n" bytes were successfully read).
  // May set "*result" to point at data in "scratch[0..n-1]", so
  // "scratch[0..n-1]" must be live when "*result" is used.
  // If an error was encountered, returns a non-OK status.
  //
  // REQUIRES: External synchronization
  virtual Status Read(
    size_t n,
    Slice *result,
    char *scratch
  ) = 0;

  // Skip "n" bytes from the file. This is guaranteed to be no
  // slower that reading the same data, but may be faster.
  //
  // If end of file is reached, skipping will stop at the end of the
  // file, and Skip will return OK.
  //
  // REQUIRES: External synchronization
  virtual Status Skip(
    uint64_t n
  ) = 0;

private:
  // No copying allowed
  SequentialFile(
    const SequentialFile &);
  void operator=(
    const SequentialFile &);
};

// A file abstraction for randomly reading the contents of a file.
class LEVELDB_DLLX RandomAccessFile {
public:
  RandomAccessFile() { }
  virtual ~RandomAccessFile();

  // Read up to "n" bytes from the file starting at "offset".
  // "scratch[0..n-1]" may be written by this routine.  Sets "*result"
  // to the data that was read (including if fewer than "n" bytes were
  // successfully read).  May set "*result" to point at data in
  // "scratch[0..n-1]", so "scratch[0..n-1]" must be live when
  // "*result" is used.  If an error was encountered, returns a non-OK
  // status.
  //
  // Safe for concurrent use by multiple threads.
  virtual Status Read(
    uint64_t offset,
    size_t n,
    Slice *result,
    char *scratch
  ) const = 0;

private:
  // No copying allowed
  RandomAccessFile(
    const RandomAccessFile &);
  void operator=(
    const RandomAccessFile &);
};

// A file abstraction for sequential writing.  The implementation
// must provide buffering since callers may append small fragments
// at a time to the file.
class LEVELDB_DLLX WritableFile {
public:
  WritableFile() { }
  virtual ~WritableFile();

  virtual Status Append(
    const Slice &data
  ) = 0;
  virtual Status Close() = 0;
  virtual Status Flush() = 0;
  virtual Status Sync() = 0;

private:
  // No copying allowed
  WritableFile(
    const WritableFile &);
  void operator=(
    const WritableFile &);
};

// Identifies a locked file.
class LEVELDB_DLLX FileLock {
public:
  FileLock() { }
  virtual ~FileLock();

private:
  // No copying allowed
  FileLock(
    const FileLock &);
  void operator=(
    const FileLock &);
};

// Log the specified data to *info_log if info_log is non-NULL.
extern void Log(Logger *info_log, const char *format, ...)
#if defined(__GNUC__) || defined(__clang__)
  __attribute__((__format__(__printf__, 2, 3)))
#endif
;

// A utility routine: write "data" to the named file.
extern Status WriteStringToFile(
  Env *env,
  const Slice &data,
  const std::string &fname);

// A utility routine: read contents of named file into *data
extern Status ReadFileToString(Env *env, const std::string &fname,
  std::string *data);

// An implementation of Env that forwards all calls to another Env.
// May be useful to clients who wish to override just part of the
// functionality of another Env.
class LEVELDB_DLLX EnvWrapper: public Env {
public:
  // Initialize an EnvWrapper that delegates all calls to *t
  explicit EnvWrapper(Env *t): target_(t) { }
  virtual ~EnvWrapper();

  // Return the target to which this Env forwards all calls
  Env *target() const {
    return target_;
  }

  // The following text is boilerplate that forwards all methods to target()
  Status NewSequentialFile(const std::string &f, SequentialFile **r) {
    return target_->NewSequentialFile(f, r);
  }
  Status NewRandomAccessFile(const std::string &f, RandomAccessFile **r) {
    return target_->NewRandomAccessFile(f, r);
  }
  Status NewWritableFile(const std::string &f, WritableFile **r) {
    return target_->NewWritableFile(f, r);
  }
  Status NewAppendableFile(const std::string &f, WritableFile **r) {
    return target_->NewAppendableFile(f, r);
  }
  bool FileExists(const std::string &f) {
    return target_->FileExists(f);
  }
  Status GetChildren(const std::string &dir, std::vector<std::string> *r) {
    return target_->GetChildren(dir, r);
  }
  Status DeleteFile(const std::string &f) {
    return target_->DeleteFile(f);
  }
  Status CreateDir(const std::string &d) {
    return target_->CreateDir(d);
  }
  Status DeleteDir(const std::string &d) {
    return target_->DeleteDir(d);
  }
  Status GetFileSize(const std::string &f, uint64_t *s) {
    return target_->GetFileSize(f, s);
  }
  Status RenameFile(const std::string &s, const std::string &t) {
    return target_->RenameFile(s, t);
  }
  Status LockFile(const std::string &f, FileLock **l) {
    return target_->LockFile(f, l);
  }
  Status UnlockFile(FileLock *l) {
    return target_->UnlockFile(l);
  }
  void Schedule(void (*f)(void *), void *a) {
    return target_->Schedule(f, a);
  }
  void StartThread(void (*f)(void *), void *a) {
    return target_->StartThread(f, a);
  }
  virtual Status GetTestDirectory(std::string *path) {
    return target_->GetTestDirectory(path);
  }
  virtual Status NewLogger(const std::string &fname, Logger **result) {
    return target_->NewLogger(fname, result);
  }
  uint64_t NowMicros() {
    return target_->NowMicros();
  }
  void SleepForMicroseconds(int micros) {
    target_->SleepForMicroseconds(micros);
  }
private:
  Env *target_;
};

// ----------------------------------------------------------------------------
// - decompress_allocator.h
// ----------------------------------------------------------------------------

class LEVELDB_DLLX DecompressAllocator {
public:
  virtual ~DecompressAllocator();

  virtual std::string get();
  virtual void release(std::string &&string);

  virtual void prune();

protected:
  std::mutex mutex;
  std::vector<std::string> stack;
};

// ----------------------------------------------------------------------------
// - dumpfile.h
// ----------------------------------------------------------------------------

// Dump the contents of the file named by fname in text format to
// *dst.  Makes a sequence of dst->Append() calls; each call is passed
// the newline-terminated text corresponding to a single item found
// in the file.
//
// Returns a non-OK result if fname does not name a leveldb storage
// file, or if the file cannot be read.
Status DumpFile(Env *env, const std::string &fname, WritableFile *dst);

// ----------------------------------------------------------------------------
// - comparator.h
// ----------------------------------------------------------------------------

// A Comparator object provides a total order across slices that are
// used as keys in an sstable or a database.  A Comparator implementation
// must be thread-safe since leveldb may invoke its methods concurrently
// from multiple threads.
class LEVELDB_DLLX Comparator {
public:
  virtual ~Comparator();

  // Three-way comparison.  Returns value:
  //   < 0 iff "a" < "b",
  //   == 0 iff "a" == "b",
  //   > 0 iff "a" > "b"
  virtual int Compare(
    const Slice &a,
    const Slice &b
  ) const = 0;

  // The name of the comparator.  Used to check for comparator
  // mismatches (i.e., a DB created with one comparator is
  // accessed using a different comparator.
  //
  // The client of this package should switch to a new name whenever
  // the comparator implementation changes in a way that will cause
  // the relative ordering of any two keys to change.
  //
  // Names starting with "leveldb." are reserved and should not be used
  // by any clients of this package.
  virtual const char *Name() const = 0;

  // Advanced functions: these are used to reduce the space requirements
  // for internal data structures like index blocks.

  // If *start < limit, changes *start to a short string in [start,limit).
  // Simple comparator implementations may return with *start unchanged,
  // i.e., an implementation of this method that does nothing is correct.
  virtual void FindShortestSeparator(
    std::string *start,
    const Slice &limit
  ) const = 0;

  // Changes *key to a short string >= *key.
  // Simple comparator implementations may return with *key unchanged,
  // i.e., an implementation of this method that does nothing is correct.
  virtual void FindShortSuccessor(
    std::string *key
  ) const = 0;
};

// Return a builtin comparator that uses lexicographic byte-wise
// ordering.  The result remains the property of this module and
// must not be deleted.
extern const Comparator *BytewiseComparator();

// ----------------------------------------------------------------------------
// - table/block_builder.h
// ----------------------------------------------------------------------------

class BlockBuilder {
public:
  explicit BlockBuilder(const Options *options);

  // Reset the contents as if the BlockBuilder was just constructed.
  void Reset();

  // REQUIRES: Finish() has not been called since the last call to Reset().
  // REQUIRES: key is larger than any previously added key
  void Add(const Slice &key, const Slice &value);

  // Finish building the block and return a slice that refers to the
  // block contents.  The returned slice will remain valid for the
  // lifetime of this builder or until Reset() is called.
  Slice Finish();

  // Returns an estimate of the current (uncompressed) size of the block
  // we are building.
  size_t CurrentSizeEstimate() const;

  // Return true iff no entries have been added since the last Reset()
  bool empty() const {
    return buffer_.empty();
  }

private:
  const Options *options_;
  std::string           buffer_;      // Destination buffer
  std::vector<uint32_t> restarts_;    // Restart points
  int                   counter_;     // Number of entries emitted since restart
  bool                  finished_;    // Has Finish() been called?
  std::string           last_key_;

  // No copying allowed
  BlockBuilder(const BlockBuilder &);
  void operator=(const BlockBuilder &);
};

// ----------------------------------------------------------------------------
// - table/block.h
// ----------------------------------------------------------------------------

class Block {
public:
  // Initialize the block with the specified contents.
  explicit Block(const BlockContents &contents);

  ~Block();

  size_t size() const {
    return size_;
  }
  Iterator *NewIterator(const Comparator *comparator);

private:
  uint32_t NumRestarts() const;

  const char *data_;
  size_t size_;
  uint32_t restart_offset_;     // Offset in data_ of restart array
  bool owned_;                  // Block owns data_[]

  // No copying allowed
  Block(const Block &);
  void operator=(const Block &);

  class Iter;
};

// ----------------------------------------------------------------------------
// - table/filter_block.h
//
// A filter block is stored near the end of a Table file.  It contains
// filters (e.g., bloom filters) for all data blocks in the table combined
// into a single filter block.
// ----------------------------------------------------------------------------

// A FilterBlockBuilder is used to construct all of the filters for a
// particular Table.  It generates a single string which is stored as
// a special block in the Table.
//
// The sequence of calls to FilterBlockBuilder must match the regexp:
//      (StartBlock AddKey*)* Finish
class FilterBlockBuilder {
public:
  explicit FilterBlockBuilder(const FilterPolicy *);

  void StartBlock(uint64_t block_offset);
  void AddKey(const Slice &key);
  Slice Finish();

private:
  void GenerateFilter();

  const FilterPolicy *policy_;
  std::string keys_;              // Flattened key contents
  std::vector<size_t> start_;     // Starting index in keys_ of each key
  std::string result_;            // Filter data computed so far
  std::vector<Slice> tmp_keys_;   // policy_->CreateFilter() argument
  std::vector<uint32_t> filter_offsets_;

  // No copying allowed
  FilterBlockBuilder(const FilterBlockBuilder &);
  void operator=(const FilterBlockBuilder &);
};

class FilterBlockReader {
public:
  // REQUIRES: "contents" and *policy must stay live while *this is live.
  FilterBlockReader(const FilterPolicy *policy, const Slice &contents);
  bool KeyMayMatch(uint64_t block_offset, const Slice &key);

private:
  const FilterPolicy *policy_;
  const char *data_;    // Pointer to filter data (at block-start)
  const char *offset_;  // Pointer to beginning of offset array (at block-end)
  size_t num_;          // Number of entries in offset array
  size_t base_lg_;      // Encoding parameter (see kFilterBaseLg in .cc file)
};

// ----------------------------------------------------------------------------
// - table/format.h
// ----------------------------------------------------------------------------

// BlockHandle is a pointer to the extent of a file that stores a data
// block or a meta block.
class BlockHandle {
public:
  BlockHandle();

  // The offset of the block in the file.
  uint64_t offset() const {
    return offset_;
  }
  void set_offset(uint64_t offset) {
    offset_ = offset;
  }

  // The size of the stored block
  uint64_t size() const {
    return size_;
  }
  void set_size(uint64_t size) {
    size_ = size;
  }

  void EncodeTo(std::string *dst) const;
  Status DecodeFrom(Slice *input);

  // Maximum encoding length of a BlockHandle
  enum {
    kMaxEncodedLength = 10 + 10
  };

private:
  uint64_t offset_;
  uint64_t size_;
};

// Footer encapsulates the fixed information stored at the tail
// end of every table file.
class Footer {
public:
  Footer() { }

  // The block handle for the metaindex block of the table
  const BlockHandle &metaindex_handle() const {
    return metaindex_handle_;
  }
  void set_metaindex_handle(const BlockHandle &h) {
    metaindex_handle_ = h;
  }

  // The block handle for the index block of the table
  const BlockHandle &index_handle() const {
    return index_handle_;
  }
  void set_index_handle(const BlockHandle &h) {
    index_handle_ = h;
  }

  void EncodeTo(std::string *dst) const;
  Status DecodeFrom(Slice *input);

  // Encoded length of a Footer.  Note that the serialization of a
  // Footer will always occupy exactly this many bytes.  It consists
  // of two block handles and a magic number.
  enum {
    kEncodedLength = 2 * BlockHandle::kMaxEncodedLength + 8
  };

private:
  BlockHandle metaindex_handle_;
  BlockHandle index_handle_;
};

// kTableMagicNumber was picked by running
//    echo http://code.google.com/p/leveldb/ | sha1sum
// and taking the leading 64 bits.
static const uint64_t kTableMagicNumber = 0xdb4775248b80fb57ull;

// 1-byte type + 32-bit crc
static const size_t kBlockTrailerSize = 5;

struct BlockContents {
  Slice data;           // Actual contents of data
  bool cachable;        // True iff data can be cached
  bool heap_allocated;  // True iff caller should delete[] data.data()
};

// Read the block identified by "handle" from "file".  On failure
// return non-OK.  On success fill *result and return OK.
extern Status ReadBlock(RandomAccessFile *file,
  const Options &dbOptions,
  const ReadOptions &options,
  const BlockHandle &handle,
  BlockContents *result);

// Implementation details follow.  Clients should ignore,

inline BlockHandle::BlockHandle()
  : offset_(~static_cast<uint64_t>(0)),
  size_(~static_cast<uint64_t>(0)) { }

// ----------------------------------------------------------------------------
// - table/iterator_wrapper.h
// ----------------------------------------------------------------------------

// A internal wrapper class with an interface similar to Iterator that
// caches the valid() and key() results for an underlying iterator.
// This can help avoid virtual function calls and also gives better
// cache locality.
class IteratorWrapper {
public:
  IteratorWrapper(): iter_(NULL), valid_(false) { }
  explicit IteratorWrapper(Iterator *iter): iter_(NULL) {
    Set(iter);
  }
  ~IteratorWrapper() {
    delete iter_;
  }
  Iterator *iter() const {
    return iter_;
  }

  // Takes ownership of "iter" and will delete it when destroyed, or
  // when Set() is invoked again.
  void Set(Iterator *iter) {
    delete iter_;
    iter_ = iter;
    if (iter_ == NULL) {
      valid_ = false;
    } else {
      Update();
    }
  }


  // Iterator interface methods
  bool Valid() const {
    return valid_;
  }
  Slice key() const {
    assert(Valid()); return key_;
  }
  Slice value() const {
    assert(Valid()); return iter_->value();
  }
  // Methods below require iter() != NULL
  Status status() const {
    assert(iter_); return iter_->status();
  }
  void Next() {
    assert(iter_); iter_->Next();        Update();
  }
  void Prev() {
    assert(iter_); iter_->Prev();        Update();
  }
  void Seek(const Slice &k) {
    assert(iter_); iter_->Seek(k);       Update();
  }
  void SeekToFirst() {
    assert(iter_); iter_->SeekToFirst(); Update();
  }
  void SeekToLast() {
    assert(iter_); iter_->SeekToLast();  Update();
  }

private:
  void Update() {
    valid_ = iter_->Valid();
    if (valid_) {
      key_ = iter_->key();
    }
  }

  Iterator *iter_;
  bool valid_;
  Slice key_;
};

// ----------------------------------------------------------------------------
// - table/merger.h
// ----------------------------------------------------------------------------

// Return an iterator that provided the union of the data in
// children[0,n-1].  Takes ownership of the child iterators and
// will delete them when the result iterator is deleted.
//
// The result does no duplicate suppression.  I.e., if a particular
// key is present in K child iterators, it will be yielded K times.
//
// REQUIRES: n >= 0
extern Iterator *NewMergingIterator(
  const Comparator *comparator,
  Iterator **children,
  int n);

// ----------------------------------------------------------------------------
// - table/two_level_iterator.h
// ----------------------------------------------------------------------------

// Return a new two level iterator.  A two-level iterator contains an
// index iterator whose values point to a sequence of blocks where
// each block is itself a sequence of key,value pairs.  The returned
// two-level iterator yields the concatenation of all key/value pairs
// in the sequence of blocks.  Takes ownership of "index_iter" and
// will delete it when no longer needed.
//
// Uses a supplied function to convert an index_iter value into
// an iterator over the contents of the corresponding block.
extern Iterator *NewTwoLevelIterator(
  Iterator *index_iter,
  Iterator *(*block_function)(
    void *arg,
    const ReadOptions &options,
    const Slice &index_value),
  void *arg,
  const ReadOptions &options);

// ----------------------------------------------------------------------------
// - db/builder.h
// ----------------------------------------------------------------------------

// Build a Table file from the contents of *iter.  The generated file
// will be named according to meta->number.  On success, the rest of
// *meta will be filled with metadata about the generated table.
// If no data is present in *iter, meta->file_size will be set to
// zero, and no Table file will be produced.
extern Status BuildTable(
  const std::string &dbname,
  Env *env,
  const Options &options,
  TableCache *table_cache,
  Iterator *iter,
  FileMetaData *meta);

// ----------------------------------------------------------------------------
// - db/db_iter.h
// ----------------------------------------------------------------------------

// Return a new iterator that converts internal keys (yielded by
// "*internal_iter") that were live at the specified "sequence" number
// into appropriate user keys.
extern Iterator *NewDBIterator(
  DBImpl *db,
  const Comparator *user_key_comparator,
  Iterator *internal_iter,
  SequenceNumber sequence,
  uint32_t seed);

// ----------------------------------------------------------------------------
// - db/dbformat.h
// ----------------------------------------------------------------------------

// Grouping of constants.  We may want to make some of these
// parameters set via options.
namespace config {
static const int kNumLevels = 7;

// Level-0 compaction is started when we hit this many files.
static const int kL0_CompactionTrigger = 4;

// Soft limit on number of level-0 files.  We slow down writes at this point.
static const int kL0_SlowdownWritesTrigger = 16;

// Maximum number of level-0 files.  We stop writes at this point.
static const int kL0_StopWritesTrigger = 64;

// Maximum level to which a new compacted memtable is pushed if it
// does not create overlap.  We try to push to level 2 to avoid the
// relatively expensive level 0=>1 compactions and to avoid some
// expensive manifest file operations.  We do not push all the way to
// the largest level since that can generate a lot of wasted disk
// space if the same key space is being repeatedly overwritten.
static const int kMaxMemCompactLevel = 2;

// Approximate gap in bytes between samples of data read during iteration.
static const int kReadBytesPeriod = 1048576;

}  // namespace config

class InternalKey;

// Value types encoded as the last component of internal keys.
// DO NOT CHANGE THESE ENUM VALUES: they are embedded in the on-disk
// data structures.
enum ValueType {
  kTypeDeletion = 0x0,
  kTypeValue = 0x1
};
// kValueTypeForSeek defines the ValueType that should be passed when
// constructing a ParsedInternalKey object for seeking to a particular
// sequence number (since we sort sequence numbers in decreasing order
// and the value type is embedded as the low 8 bits in the sequence
// number in internal keys, we need to use the highest-numbered
// ValueType, not the lowest).
static const ValueType kValueTypeForSeek = kTypeValue;

// We leave eight bits empty at the bottom so a type and sequence#
// can be packed together into 64-bits.
static const SequenceNumber kMaxSequenceNumber =
((0x1ull << 56) - 1);

struct ParsedInternalKey {
  Slice user_key;
  SequenceNumber sequence;
  ValueType type;

  ParsedInternalKey() { }  // Intentionally left uninitialized (for speed)
  ParsedInternalKey(const Slice &u, const SequenceNumber &seq, ValueType t)
    : user_key(u), sequence(seq), type(t) { }
  std::string DebugString() const;
};

// Return the length of the encoding of "key".
inline size_t InternalKeyEncodingLength(const ParsedInternalKey &key) {
  return key.user_key.size() + 8;
}

// Append the serialization of "key" to *result.
extern void AppendInternalKey(std::string *result,
  const ParsedInternalKey &key);

// Attempt to parse an internal key from "internal_key".  On success,
// stores the parsed data in "*result", and returns true.
//
// On error, returns false, leaves "*result" in an undefined state.
extern bool ParseInternalKey(const Slice &internal_key,
  ParsedInternalKey *result);

// Returns the user key portion of an internal key.
inline Slice ExtractUserKey(const Slice &internal_key) {
  assert(internal_key.size() >= 8);
  return Slice(internal_key.data(), internal_key.size() - 8);
}

inline ValueType ExtractValueType(const Slice &internal_key) {
  assert(internal_key.size() >= 8);
  const size_t n = internal_key.size();
  uint64_t num = DecodeFixed64(internal_key.data() + n - 8);
  unsigned char c = num & 0xff;
  return static_cast<ValueType>(c);
}

// A comparator for internal keys that uses a specified comparator for
// the user key portion and breaks ties by decreasing sequence number.
class InternalKeyComparator: public Comparator {
private:
  const Comparator *user_comparator_;
public:
  explicit InternalKeyComparator(const Comparator *c): user_comparator_(c) { }
  virtual const char *Name() const;
  virtual int Compare(const Slice &a, const Slice &b) const;
  virtual void FindShortestSeparator(
    std::string *start,
    const Slice &limit) const;
  virtual void FindShortSuccessor(std::string *key) const;

  const Comparator *user_comparator() const {
    return user_comparator_;
  }

  int Compare(const InternalKey &a, const InternalKey &b) const;
};

// Filter policy wrapper that converts from internal keys to user keys
class InternalFilterPolicy: public FilterPolicy {
private:
  const FilterPolicy *const user_policy_;
public:
  explicit InternalFilterPolicy(const FilterPolicy *p): user_policy_(p) { }
  virtual const char *Name() const;
  virtual void CreateFilter(const Slice *keys, int n, std::string *dst) const;
  virtual bool KeyMayMatch(const Slice &key, const Slice &filter) const;
};

// Modules in this directory should keep internal keys wrapped inside
// the following class instead of plain strings so that we do not
// incorrectly use string comparisons instead of an InternalKeyComparator.
class InternalKey {
private:
  std::string rep_;
public:
  InternalKey() { }   // Leave rep_ as empty to indicate it is invalid
  InternalKey(const Slice &user_key, SequenceNumber s, ValueType t) {
    AppendInternalKey(&rep_, ParsedInternalKey(user_key, s, t));
  }

  void DecodeFrom(const Slice &s) {
    rep_.assign(s.data(), s.size());
  }
  Slice Encode() const {
    assert(!rep_.empty());
    return rep_;
  }

  Slice user_key() const {
    return ExtractUserKey(rep_);
  }

  void SetFrom(const ParsedInternalKey &p) {
    rep_.clear();
    AppendInternalKey(&rep_, p);
  }

  void Clear() {
    rep_.clear();
  }

  std::string DebugString() const;
};

inline int InternalKeyComparator::Compare(
  const InternalKey &a, const InternalKey &b) const {
  return Compare(a.Encode(), b.Encode());
}

inline bool ParseInternalKey(const Slice &internal_key,
  ParsedInternalKey *result) {
  const size_t n = internal_key.size();
  if (n < 8) return false;
  uint64_t num = DecodeFixed64(internal_key.data() + n - 8);
  unsigned char c = num & 0xff;
  result->sequence = num >> 8;
  result->type = static_cast<ValueType>(c);
  result->user_key = Slice(internal_key.data(), n - 8);
  return (c <= static_cast<unsigned char>(kTypeValue));
}

// A helper class useful for DBImpl::Get()
class LookupKey {
public:
  // Initialize *this for looking up user_key at a snapshot with
  // the specified sequence number.
  LookupKey(const Slice &user_key, SequenceNumber sequence);

  ~LookupKey();

  // Return a key suitable for lookup in a MemTable.
  Slice memtable_key() const {
    return Slice(start_, end_ - start_);
  }

  // Return an internal key (suitable for passing to an internal iterator)
  Slice internal_key() const {
    return Slice(kstart_, end_ - kstart_);
  }

  // Return the user key
  Slice user_key() const {
    return Slice(kstart_, end_ - kstart_ - 8);
  }

private:
  // We construct a char array of the form:
  //    klength  varint32               <-- start_
  //    userkey  char[klength]          <-- kstart_
  //    tag      uint64
  //                                    <-- end_
  // The array is a suitable MemTable key.
  // The suffix starting with "userkey" can be used as an InternalKey.
  const char *start_;
  const char *kstart_;
  const char *end_;
  char space_[200];      // Avoid allocation for short keys

  // No copying allowed
  LookupKey(const LookupKey &);
  void operator=(const LookupKey &);
};

inline LookupKey::~LookupKey() {
  if (start_ != space_) delete[] start_;
}

// ----------------------------------------------------------------------------
// - db/filename.h
//
// File names used by DB code
// ----------------------------------------------------------------------------

enum FileType {
  kLogFile,
  kDBLockFile,
  kTableFile,
  kDescriptorFile,
  kCurrentFile,
  kTempFile,
  kInfoLogFile  // Either the current one, or an old one
};

// Return the name of the log file with the specified number
// in the db named by "dbname".  The result will be prefixed with
// "dbname".
extern std::string LogFileName(const std::string &dbname, uint64_t number);

// Return the name of the sstable with the specified number
// in the db named by "dbname".  The result will be prefixed with
// "dbname".
extern std::string TableFileName(const std::string &dbname, uint64_t number);

// Return the legacy file name for an sstable with the specified number
// in the db named by "dbname". The result will be prefixed with
// "dbname".
extern std::string SSTTableFileName(const std::string &dbname, uint64_t number);

// Return the name of the descriptor file for the db named by
// "dbname" and the specified incarnation number.  The result will be
// prefixed with "dbname".
extern std::string DescriptorFileName(const std::string &dbname,
  uint64_t number);

// Return the name of the current file.  This file contains the name
// of the current manifest file.  The result will be prefixed with
// "dbname".
extern std::string CurrentFileName(const std::string &dbname);

// Return the name of the lock file for the db named by
// "dbname".  The result will be prefixed with "dbname".
extern std::string LockFileName(const std::string &dbname);

// Return the name of a temporary file owned by the db named "dbname".
// The result will be prefixed with "dbname".
extern std::string TempFileName(const std::string &dbname, uint64_t number);

// Return the name of the info log file for "dbname".
extern std::string InfoLogFileName(const std::string &dbname);

// Return the name of the old info log file for "dbname".
extern std::string OldInfoLogFileName(const std::string &dbname);

// If filename is a leveldb file, store the type of the file in *type.
// The number encoded in the filename is stored in *number.  If the
// filename was successfully parsed, returns true.  Else return false.
extern bool ParseFileName(const std::string &filename,
  uint64_t *number,
  FileType *type);

// Make the CURRENT file point to the descriptor file with the
// specified number.
extern Status SetCurrentFile(Env *env, const std::string &dbname,
  uint64_t descriptor_number);

// ----------------------------------------------------------------------------
// - db/log_format.h
//
// Log format information shared by reader and writer.
// See ../doc/log_format.md for more detail.
// ----------------------------------------------------------------------------

namespace log {

enum RecordType {
  // Zero is reserved for preallocated files
  kZeroType = 0,

  kFullType = 1,

  // For fragments
  kFirstType = 2,
  kMiddleType = 3,
  kLastType = 4
};
static const int kMaxRecordType = kLastType;

static const int kBlockSize = 32768;

// Header is checksum (4 bytes), length (2 bytes), type (1 byte).
static const int kHeaderSize = 4 + 2 + 1;

// ----------------------------------------------------------------------------
// - db/log_reader.h
// ----------------------------------------------------------------------------

class Reader {
public:
  // Interface for reporting errors.
  class Reporter {
  public:
    virtual ~Reporter();

    // Some corruption was detected.  "size" is the approximate number
    // of bytes dropped due to the corruption.
    virtual void Corruption(size_t bytes, const Status &status) = 0;
  };

  // Create a reader that will return log records from "*file".
  // "*file" must remain live while this Reader is in use.
  //
  // If "reporter" is non-NULL, it is notified whenever some data is
  // dropped due to a detected corruption.  "*reporter" must remain
  // live while this Reader is in use.
  //
  // If "checksum" is true, verify checksums if available.
  //
  // The Reader will start reading at the first record located at physical
  // position >= initial_offset within the file.
  Reader(SequentialFile *file, Reporter *reporter, bool checksum,
    uint64_t initial_offset);

  ~Reader();

  // Read the next record into *record.  Returns true if read
  // successfully, false if we hit end of the input.  May use
  // "*scratch" as temporary storage.  The contents filled in *record
  // will only be valid until the next mutating operation on this
  // reader or the next mutation to *scratch.
  bool ReadRecord(Slice *record, std::string *scratch);

  // Returns the physical offset of the last record returned by ReadRecord.
  //
  // Undefined before the first call to ReadRecord.
  uint64_t LastRecordOffset();

private:
  SequentialFile *const file_;
  Reporter *const reporter_;
  bool const checksum_;
  char *const backing_store_;
  Slice buffer_;
  bool eof_;   // Last Read() indicated EOF by returning < kBlockSize

  // Offset of the last record returned by ReadRecord.
  uint64_t last_record_offset_;
  // Offset of the first location past the end of buffer_.
  uint64_t end_of_buffer_offset_;

  // Offset at which to start looking for the first record to return
  uint64_t const initial_offset_;

  // True if we are resynchronizing after a seek (initial_offset_ > 0). In
  // particular, a run of kMiddleType and kLastType records can be silently
  // skipped in this mode
  bool resyncing_;

  // Extend record types with the following special values
  enum {
    kEof = kMaxRecordType + 1,
    // Returned whenever we find an invalid physical record.
    // Currently there are three situations in which this happens:
    // * The record has an invalid CRC (ReadPhysicalRecord reports a drop)
    // * The record is a 0-length record (No drop is reported)
    // * The record is below constructor's initial_offset (No drop is reported)
    kBadRecord = kMaxRecordType + 2
  };

  // Skips all blocks that are completely before "initial_offset_".
  //
  // Returns true on success. Handles reporting.
  bool SkipToInitialBlock();

  // Return type, or one of the preceding special values
  unsigned int ReadPhysicalRecord(Slice *result);

  // Reports dropped bytes to the reporter.
  // buffer_ must be updated to remove the dropped bytes prior to invocation.
  void ReportCorruption(uint64_t bytes, const char *reason);
  void ReportDrop(uint64_t bytes, const Status &reason);

  // No copying allowed
  Reader(const Reader &);
  void operator=(const Reader &);
};

// ----------------------------------------------------------------------------
// - db/log_writer.h
// ----------------------------------------------------------------------------

class Writer {
public:
  // Create a writer that will append data to "*dest".
  // "*dest" must be initially empty.
  // "*dest" must remain live while this Writer is in use.
  explicit Writer(WritableFile *dest);

  // Create a writer that will append data to "*dest".
  // "*dest" must have initial length "dest_length".
  // "*dest" must remain live while this Writer is in use.
  Writer(WritableFile *dest, uint64_t dest_length);

  ~Writer();

  Status AddRecord(const Slice &slice);

private:
  WritableFile *dest_;
  int block_offset_;       // Current offset in block

  // crc32c values for all supported record types.  These are
  // pre-computed to reduce the overhead of computing the crc of the
  // record type stored in the header.
  uint32_t type_crc_[kMaxRecordType + 1];

  Status EmitPhysicalRecord(RecordType type, const char *ptr, size_t length);

  // No copying allowed
  Writer(const Writer &);
  void operator=(const Writer &);
};

} // namespace log

  // ----------------------------------------------------------------------------
  // - db/skiplist.h
  //
  // Thread safety
  // -------------
  //
  // Writes require external synchronization, most likely a mutex.
  // Reads require a guarantee that the SkipList will not be destroyed
  // while the read is in progress.  Apart from that, reads progress
  // without any internal locking or synchronization.
  //
  // Invariants:
  //
  // (1) Allocated nodes are never deleted until the SkipList is
  // destroyed.  This is trivially guaranteed by the code since we
  // never delete any skip list nodes.
  //
  // (2) The contents of a Node except for the next/prev pointers are
  // immutable after the Node has been linked into the SkipList.
  // Only Insert() modifies the list, and it is careful to initialize
  // a node and use release-stores to publish the nodes in one or
  // more lists.
  //
  // ... prev vs. next pointer ordering ...
  // ----------------------------------------------------------------------------

template<typename Key, class Comparator>
class SkipList {
private:
  struct Node;

public:
  // Create a new SkipList object that will use "cmp" for comparing keys,
  // and will allocate memory using "*arena".  Objects allocated in the arena
  // must remain allocated for the lifetime of the skiplist object.
  explicit SkipList(Comparator cmp, Arena *arena);

  // Insert key into the list.
  // REQUIRES: nothing that compares equal to key is currently in the list.
  void Insert(const Key &key);

  // Returns true iff an entry that compares equal to key is in the list.
  bool Contains(const Key &key) const;

  // Iteration over the contents of a skip list
  class Iterator {
  public:
    // Initialize an iterator over the specified list.
    // The returned iterator is not valid.
    explicit Iterator(const SkipList *list);

    // Returns true iff the iterator is positioned at a valid node.
    bool Valid() const;

    // Returns the key at the current position.
    // REQUIRES: Valid()
    const Key &key() const;

    // Advances to the next position.
    // REQUIRES: Valid()
    void Next();

    // Advances to the previous position.
    // REQUIRES: Valid()
    void Prev();

    // Advance to the first entry with a key >= target
    void Seek(const Key &target);

    // Position at the first entry in list.
    // Final state of iterator is Valid() iff list is not empty.
    void SeekToFirst();

    // Position at the last entry in list.
    // Final state of iterator is Valid() iff list is not empty.
    void SeekToLast();

  private:
    const SkipList *list_;
    Node *node_;
    // Intentionally copyable
  };

private:
  enum {
    kMaxHeight = 12
  };

  // Immutable after construction
  Comparator const compare_;
  Arena *const arena_;    // Arena used for allocations of nodes

  Node *const head_;

  // Modified only by Insert().  Read racily by readers, but stale
  // values are ok.
  port::AtomicPointer max_height_;   // Height of the entire list

  inline int GetMaxHeight() const {
    return static_cast<int>(
      reinterpret_cast<intptr_t>(max_height_.NoBarrier_Load()));
  }

  // Read/written only by Insert().
  Random rnd_;

  Node *NewNode(const Key &key, int height);
  int RandomHeight();
  bool Equal(const Key &a, const Key &b) const {
    return (compare_(a, b) == 0);
  }

  // Return true if key is greater than the data stored in "n"
  bool KeyIsAfterNode(const Key &key, Node *n) const;

  // Return the earliest node that comes at or after key.
  // Return NULL if there is no such node.
  //
  // If prev is non-NULL, fills prev[level] with pointer to previous
  // node at "level" for every level in [0..max_height_-1].
  Node *FindGreaterOrEqual(const Key &key, Node **prev) const;

  // Return the latest node with a key < key.
  // Return head_ if there is no such node.
  Node *FindLessThan(const Key &key) const;

  // Return the last node in the list.
  // Return head_ if list is empty.
  Node *FindLast() const;

  // No copying allowed
  SkipList(const SkipList &);
  void operator=(const SkipList &);
};

// Implementation details follow
template<typename Key, class Comparator>
struct SkipList<Key, Comparator>::Node {
  explicit Node(const Key &k): key(k) { }

  Key const key;

  // Accessors/mutators for links.  Wrapped in methods so we can
  // add the appropriate barriers as necessary.
  Node *Next(int n) {
    assert(n >= 0);
    // Use an 'acquire load' so that we observe a fully initialized
    // version of the returned Node.
    return reinterpret_cast<Node *>(next_[n].Acquire_Load());
  }
  void SetNext(int n, Node *x) {
    assert(n >= 0);
    // Use a 'release store' so that anybody who reads through this
    // pointer observes a fully initialized version of the inserted node.
    next_[n].Release_Store(x);
  }

  // No-barrier variants that can be safely used in a few locations.
  Node *NoBarrier_Next(int n) {
    assert(n >= 0);
    return reinterpret_cast<Node *>(next_[n].NoBarrier_Load());
  }
  void NoBarrier_SetNext(int n, Node *x) {
    assert(n >= 0);
    next_[n].NoBarrier_Store(x);
  }

private:
  // Array of length equal to the node height.  next_[0] is lowest level link.
  port::AtomicPointer next_[1];
};

template<typename Key, class Comparator>
typename SkipList<Key, Comparator>::Node *
SkipList<Key, Comparator>::NewNode(const Key &key, int height) {
  char *mem = arena_->AllocateAligned(
    sizeof(Node) + sizeof(port::AtomicPointer) * (height - 1));
  return new (mem) Node(key);
}

template<typename Key, class Comparator>
inline SkipList<Key, Comparator>::Iterator::Iterator(const SkipList *list) {
  list_ = list;
  node_ = NULL;
}

template<typename Key, class Comparator>
inline bool SkipList<Key, Comparator>::Iterator::Valid() const {
  return node_ != NULL;
}

template<typename Key, class Comparator>
inline const Key &SkipList<Key, Comparator>::Iterator::key() const {
  assert(Valid());
  return node_->key;
}

template<typename Key, class Comparator>
inline void SkipList<Key, Comparator>::Iterator::Next() {
  assert(Valid());
  node_ = node_->Next(0);
}

template<typename Key, class Comparator>
inline void SkipList<Key, Comparator>::Iterator::Prev() {
  // Instead of using explicit "prev" links, we just search for the
  // last node that falls before key.
  assert(Valid());
  node_ = list_->FindLessThan(node_->key);
  if (node_ == list_->head_) {
    node_ = NULL;
  }
}

template<typename Key, class Comparator>
inline void SkipList<Key, Comparator>::Iterator::Seek(const Key &target) {
  node_ = list_->FindGreaterOrEqual(target, NULL);
}

template<typename Key, class Comparator>
inline void SkipList<Key, Comparator>::Iterator::SeekToFirst() {
  node_ = list_->head_->Next(0);
}

template<typename Key, class Comparator>
inline void SkipList<Key, Comparator>::Iterator::SeekToLast() {
  node_ = list_->FindLast();
  if (node_ == list_->head_) {
    node_ = NULL;
  }
}

template<typename Key, class Comparator>
int SkipList<Key, Comparator>::RandomHeight() {
  // Increase height with probability 1 in kBranching
  static const unsigned int kBranching = 4;
  int height = 1;
  while (height < kMaxHeight && ((rnd_.Next() % kBranching) == 0)) {
    height++;
  }
  assert(height > 0);
  assert(height <= kMaxHeight);
  return height;
}

template<typename Key, class Comparator>
bool SkipList<Key, Comparator>::KeyIsAfterNode(const Key &key, Node *n) const {
  // NULL n is considered infinite
  return (n != NULL) && (compare_(n->key, key) < 0);
}

template<typename Key, class Comparator>
typename SkipList<Key, Comparator>::Node *SkipList<Key, Comparator>::FindGreaterOrEqual(const Key &key, Node **prev)
const {
  Node *x = head_;
  int level = GetMaxHeight() - 1;
  while (true) {
    Node *next = x->Next(level);
    if (KeyIsAfterNode(key, next)) {
      // Keep searching in this list
      x = next;
    } else {
      if (prev != NULL) prev[level] = x;
      if (level == 0) {
        return next;
      } else {
        // Switch to next list
        level--;
      }
    }
  }
}

template<typename Key, class Comparator>
typename SkipList<Key, Comparator>::Node *
SkipList<Key, Comparator>::FindLessThan(const Key &key) const {
  Node *x = head_;
  int level = GetMaxHeight() - 1;
  while (true) {
    assert(x == head_ || compare_(x->key, key) < 0);
    Node *next = x->Next(level);
    if (next == NULL || compare_(next->key, key) >= 0) {
      if (level == 0) {
        return x;
      } else {
        // Switch to next list
        level--;
      }
    } else {
      x = next;
    }
  }
}

template<typename Key, class Comparator>
typename SkipList<Key, Comparator>::Node *SkipList<Key, Comparator>::FindLast()
const {
  Node *x = head_;
  int level = GetMaxHeight() - 1;
  while (true) {
    Node *next = x->Next(level);
    if (next == NULL) {
      if (level == 0) {
        return x;
      } else {
        // Switch to next list
        level--;
      }
    } else {
      x = next;
    }
  }
}

template<typename Key, class Comparator>
SkipList<Key, Comparator>::SkipList(Comparator cmp, Arena *arena)
  : compare_(cmp),
  arena_(arena),
  head_(NewNode(0 /* any key will do */, kMaxHeight)),
  max_height_(reinterpret_cast<void *>(1)),
  rnd_(0xdeadbeef) {
  for (int i = 0; i < kMaxHeight; i++) {
    head_->SetNext(i, NULL);
  }
}

template<typename Key, class Comparator>
void SkipList<Key, Comparator>::Insert(const Key &key) {
  // TODO(opt): We can use a barrier-free variant of FindGreaterOrEqual()
  // here since Insert() is externally synchronized.
  Node *prev[kMaxHeight];
  Node *x = FindGreaterOrEqual(key, prev);

  // Our data structure does not allow duplicate insertion
  assert(x == NULL || !Equal(key, x->key));

  int height = RandomHeight();
  if (height > GetMaxHeight()) {
    for (int i = GetMaxHeight(); i < height; i++) {
      prev[i] = head_;
    }
    //fprintf(stderr, "Change height from %d to %d\n", max_height_, height);

    // It is ok to mutate max_height_ without any synchronization
    // with concurrent readers.  A concurrent reader that observes
    // the new value of max_height_ will see either the old value of
    // new level pointers from head_ (NULL), or a new value set in
    // the loop below.  In the former case the reader will
    // immediately drop to the next level since NULL sorts after all
    // keys.  In the latter case the reader will use the new node.
    max_height_.NoBarrier_Store(reinterpret_cast<void *>(height));
  }

  x = NewNode(key, height);
  for (int i = 0; i < height; i++) {
    // NoBarrier_SetNext() suffices since we will add a barrier when
    // we publish a pointer to "x" in prev[i].
    x->NoBarrier_SetNext(i, prev[i]->NoBarrier_Next(i));
    prev[i]->SetNext(i, x);
  }
}

template<typename Key, class Comparator>
bool SkipList<Key, Comparator>::Contains(const Key &key) const {
  Node *x = FindGreaterOrEqual(key, NULL);
  if (x != NULL && Equal(key, x->key)) {
    return true;
  } else {
    return false;
  }
}

// ----------------------------------------------------------------------------
// - db/memtable.h
// ----------------------------------------------------------------------------

class MemTable {
public:
  // MemTables are reference counted.  The initial reference count
  // is zero and the caller must call Ref() at least once.
  explicit MemTable(const InternalKeyComparator &comparator);

  // Increase reference count.
  void Ref() {
    ++refs_;
  }

  // Drop reference count.  Delete if no more references exist.
  void Unref() {
    --refs_;
    assert(refs_ >= 0);
    if (refs_ <= 0) {
      delete this;
    }
  }

  // Returns an estimate of the number of bytes of data in use by this
  // data structure. It is safe to call when MemTable is being modified.
  size_t ApproximateMemoryUsage();

  // Return an iterator that yields the contents of the memtable.
  //
  // The caller must ensure that the underlying MemTable remains live
  // while the returned iterator is live.  The keys returned by this
  // iterator are internal keys encoded by AppendInternalKey in the
  // db/format.{h,cc} module.
  Iterator *NewIterator();

  // Add an entry into memtable that maps key to value at the
  // specified sequence number and with the specified type.
  // Typically value will be empty if type==kTypeDeletion.
  void Add(SequenceNumber seq, ValueType type,
    const Slice &key,
    const Slice &value);

  // If memtable contains a value for key, store it in *value and return true.
  // If memtable contains a deletion for key, store a NotFound() error
  // in *status and return true.
  // Else, return false.
  bool Get(const LookupKey &key, std::string *value, Status *s);

private:
  ~MemTable();  // Private since only Unref() should be used to delete it

  struct KeyComparator {
    const InternalKeyComparator comparator;
    explicit KeyComparator(const InternalKeyComparator &c): comparator(c) { }
    int operator()(const char *a, const char *b) const;
  };
  friend class MemTableIterator;
  friend class MemTableBackwardIterator;

  typedef SkipList<const char *, KeyComparator> Table;

  KeyComparator comparator_;
  int refs_;
  Arena arena_;
  Table table_;

  // No copying allowed
  MemTable(const MemTable &);
  void operator=(const MemTable &);
};

// ----------------------------------------------------------------------------
// - db/snapshot.h
// ----------------------------------------------------------------------------

// Snapshots are kept in a doubly-linked list in the DB.
// Each SnapshotImpl corresponds to a particular sequence number.
class SnapshotImpl: public Snapshot {
public:
  SequenceNumber number_;  // const after creation

private:
  friend class SnapshotList;

  // SnapshotImpl is kept in a doubly-linked circular list
  SnapshotImpl *prev_;
  SnapshotImpl *next_;

  SnapshotList *list_;                 // just for sanity checks
};

class SnapshotList {
public:
  SnapshotList() {
    list_.prev_ = &list_;
    list_.next_ = &list_;
  }

  bool empty() const {
    return list_.next_ == &list_;
  }
  SnapshotImpl *oldest() const {
    assert(!empty()); return list_.next_;
  }
  SnapshotImpl *newest() const {
    assert(!empty()); return list_.prev_;
  }

  const SnapshotImpl *New(SequenceNumber seq) {
    SnapshotImpl *s = new SnapshotImpl;
    s->number_ = seq;
    s->list_ = this;
    s->next_ = &list_;
    s->prev_ = list_.prev_;
    s->prev_->next_ = s;
    s->next_->prev_ = s;
    return s;
  }

  void Delete(const SnapshotImpl *s) {
    assert(s->list_ == this);
    s->prev_->next_ = s->next_;
    s->next_->prev_ = s->prev_;
    delete s;
  }

private:
  // Dummy head of doubly-linked list of snapshots
  SnapshotImpl list_;
};

// ----------------------------------------------------------------------------
// - db/table_cache.h
//
// Thread-safe (provides internal synchronization)
// ----------------------------------------------------------------------------

class TableCache {
public:
  TableCache(const std::string &dbname, const Options *options, int entries);
  ~TableCache();

  // Return an iterator for the specified file number (the corresponding
  // file length must be exactly "file_size" bytes).  If "tableptr" is
  // non-NULL, also sets "*tableptr" to point to the Table object
  // underlying the returned iterator, or NULL if no Table object underlies
  // the returned iterator.  The returned "*tableptr" object is owned by
  // the cache and should not be deleted, and is valid for as long as the
  // returned iterator is live.
  Iterator *NewIterator(const ReadOptions &options,
    uint64_t file_number,
    uint64_t file_size,
    Table **tableptr = NULL);

  // If a seek to internal key "k" in specified file finds an entry,
  // call (*handle_result)(arg, found_key, found_value).
  Status Get(const ReadOptions &options,
    uint64_t file_number,
    uint64_t file_size,
    const Slice &k,
    void *arg,
    void (*handle_result)(void *, const Slice &, const Slice &));

  // Evict any entry for the specified file number
  void Evict(uint64_t file_number);

private:
  Env *const env_;
  const std::string dbname_;
  const Options *options_;
  Cache *cache_;

  Status FindTable(uint64_t file_number, uint64_t file_size, Cache::Handle **);
};

// ----------------------------------------------------------------------------
// - db/version_edit.h
// ----------------------------------------------------------------------------

struct FileMetaData {
  int refs;
  int allowed_seeks;          // Seeks allowed until compaction
  uint64_t number;
  uint64_t file_size;         // File size in bytes
  InternalKey smallest;       // Smallest internal key served by table
  InternalKey largest;        // Largest internal key served by table

  FileMetaData(): refs(0), allowed_seeks(1 << 30), file_size(0) { }
};

class VersionEdit {
public:
  VersionEdit() {
    Clear();
  }
  ~VersionEdit() { }

  void Clear();

  void SetComparatorName(const Slice &name) {
    has_comparator_ = true;
    comparator_ = name.ToString();
  }
  void SetLogNumber(uint64_t num) {
    has_log_number_ = true;
    log_number_ = num;
  }
  void SetPrevLogNumber(uint64_t num) {
    has_prev_log_number_ = true;
    prev_log_number_ = num;
  }
  void SetNextFile(uint64_t num) {
    has_next_file_number_ = true;
    next_file_number_ = num;
  }
  void SetLastSequence(SequenceNumber seq) {
    has_last_sequence_ = true;
    last_sequence_ = seq;
  }
  void SetCompactPointer(int level, const InternalKey &key) {
    compact_pointers_.push_back(std::make_pair(level, key));
  }

  // Add the specified file at the specified number.
  // REQUIRES: This version has not been saved (see VersionSet::SaveTo)
  // REQUIRES: "smallest" and "largest" are smallest and largest keys in file
  void AddFile(int level, uint64_t file,
    uint64_t file_size,
    const InternalKey &smallest,
    const InternalKey &largest) {
    FileMetaData f;
    f.number = file;
    f.file_size = file_size;
    f.smallest = smallest;
    f.largest = largest;
    new_files_.push_back(std::make_pair(level, f));
  }

  // Delete the specified "file" from the specified "level".
  void DeleteFile(int level, uint64_t file) {
    deleted_files_.insert(std::make_pair(level, file));
  }

  void EncodeTo(std::string *dst) const;
  Status DecodeFrom(const Slice &src);

  std::string DebugString() const;

private:
  friend class VersionSet;

  typedef std::set< std::pair<int, uint64_t> > DeletedFileSet;

  std::string comparator_;
  uint64_t log_number_;
  uint64_t prev_log_number_;
  uint64_t next_file_number_;
  SequenceNumber last_sequence_;
  bool has_comparator_;
  bool has_log_number_;
  bool has_prev_log_number_;
  bool has_next_file_number_;
  bool has_last_sequence_;

  std::vector< std::pair<int, InternalKey> > compact_pointers_;
  DeletedFileSet deleted_files_;
  std::vector< std::pair<int, FileMetaData> > new_files_;
};

// ----------------------------------------------------------------------------
// - db/version_set.h
// ----------------------------------------------------------------------------

// Return the smallest index i such that files[i]->largest >= key.
// Return files.size() if there is no such file.
// REQUIRES: "files" contains a sorted list of non-overlapping files.
extern int FindFile(const InternalKeyComparator &icmp,
  const std::vector<FileMetaData *> &files,
  const Slice &key);

// Returns true iff some file in "files" overlaps the user key range
// [*smallest,*largest].
// smallest==NULL represents a key smaller than all keys in the DB.
// largest==NULL represents a key largest than all keys in the DB.
// REQUIRES: If disjoint_sorted_files, files[] contains disjoint ranges
//           in sorted order.
extern bool SomeFileOverlapsRange(
  const InternalKeyComparator &icmp,
  bool disjoint_sorted_files,
  const std::vector<FileMetaData *> &files,
  const Slice *smallest_user_key,
  const Slice *largest_user_key);

class Version {
public:
  // Append to *iters a sequence of iterators that will
  // yield the contents of this Version when merged together.
  // REQUIRES: This version has been saved (see VersionSet::SaveTo)
  void AddIterators(const ReadOptions &, std::vector<Iterator *> *iters);

  // Lookup the value for key.  If found, store it in *val and
  // return OK.  Else return a non-OK status.  Fills *stats.
  // REQUIRES: lock is not held
  struct GetStats {
    FileMetaData *seek_file;
    int seek_file_level;
  };
  Status Get(const ReadOptions &, const LookupKey &key, std::string *val,
    GetStats *stats);

  // Adds "stats" into the current state.  Returns true if a new
  // compaction may need to be triggered, false otherwise.
  // REQUIRES: lock is held
  bool UpdateStats(const GetStats &stats);

  // Record a sample of bytes read at the specified internal key.
  // Samples are taken approximately once every config::kReadBytesPeriod
  // bytes.  Returns true if a new compaction may need to be triggered.
  // REQUIRES: lock is held
  bool RecordReadSample(Slice key);

  // Reference count management (so Versions do not disappear out from
  // under live iterators)
  void Ref();
  void Unref();

  void GetOverlappingInputs(
    int level,
    const InternalKey *begin,         // NULL means before all keys
    const InternalKey *end,           // NULL means after all keys
    std::vector<FileMetaData *> *inputs);

  // Returns true iff some file in the specified level overlaps
  // some part of [*smallest_user_key,*largest_user_key].
  // smallest_user_key==NULL represents a key smaller than all keys in the DB.
  // largest_user_key==NULL represents a key largest than all keys in the DB.
  bool OverlapInLevel(int level,
    const Slice *smallest_user_key,
    const Slice *largest_user_key);

  // Return the level at which we should place a new memtable compaction
  // result that covers the range [smallest_user_key,largest_user_key].
  int PickLevelForMemTableOutput(const Slice &smallest_user_key,
    const Slice &largest_user_key);

  int NumFiles(int level) const {
    return (int)files_[level].size();
  }

  // Return a human readable string that describes this version's contents.
  std::string DebugString() const;

private:
  friend class Compaction;
  friend class VersionSet;

  class LevelFileNumIterator;
  Iterator *NewConcatenatingIterator(const ReadOptions &, int level) const;

  // Call func(arg, level, f) for every file that overlaps user_key in
  // order from newest to oldest.  If an invocation of func returns
  // false, makes no more calls.
  //
  // REQUIRES: user portion of internal_key == user_key.
  void ForEachOverlapping(Slice user_key, Slice internal_key,
    void *arg,
    bool (*func)(void *, int, FileMetaData *));

  VersionSet *vset_;            // VersionSet to which this Version belongs
  Version *next_;               // Next version in linked list
  Version *prev_;               // Previous version in linked list
  int refs_;                    // Number of live refs to this version

  // List of files per level
  std::vector<FileMetaData *> files_[config::kNumLevels];

  // Next file to compact based on seek stats.
  FileMetaData *file_to_compact_;
  int file_to_compact_level_;

  // Level that should be compacted next and its compaction score.
  // Score < 1 means compaction is not strictly needed.  These fields
  // are initialized by Finalize().
  double compaction_score_;
  int compaction_level_;

  explicit Version(VersionSet *vset)
    : vset_(vset), next_(this), prev_(this), refs_(0),
    file_to_compact_(NULL),
    file_to_compact_level_(-1),
    compaction_score_(-1),
    compaction_level_(-1) { }

  ~Version();

  // No copying allowed
  Version(const Version &);
  void operator=(const Version &);
};

class VersionSet {
public:
  VersionSet(const std::string &dbname,
    const Options *options,
    TableCache *table_cache,
    const InternalKeyComparator *);
  ~VersionSet();

  // Apply *edit to the current version to form a new descriptor that
  // is both saved to persistent state and installed as the new
  // current version.  Will release *mu while actually writing to the file.
  // REQUIRES: *mu is held on entry.
  // REQUIRES: no other thread concurrently calls LogAndApply()
  Status LogAndApply(VersionEdit *edit, port::Mutex *mu)
    EXCLUSIVE_LOCKS_REQUIRED(mu);

  // Recover the last saved descriptor from persistent storage.
  Status Recover(bool *save_manifest);

  // Return the current version.
  Version *current() const {
    return current_;
  }

  // Return the current manifest file number
  uint64_t ManifestFileNumber() const {
    return manifest_file_number_;
  }

  // Allocate and return a new file number
  uint64_t NewFileNumber() {
    return next_file_number_++;
  }

  // Arrange to reuse "file_number" unless a newer file number has
  // already been allocated.
  // REQUIRES: "file_number" was returned by a call to NewFileNumber().
  void ReuseFileNumber(uint64_t file_number) {
    if (next_file_number_ == file_number + 1) {
      next_file_number_ = file_number;
    }
  }

  // Return the number of Table files at the specified level.
  int NumLevelFiles(int level) const;

  // Return the combined file size of all files at the specified level.
  int64_t NumLevelBytes(int level) const;

  // Return the last sequence number.
  uint64_t LastSequence() const {
    return last_sequence_;
  }

  // Set the last sequence number to s.
  void SetLastSequence(uint64_t s) {
    assert(s >= last_sequence_);
    last_sequence_ = s;
  }

  // Mark the specified file number as used.
  void MarkFileNumberUsed(uint64_t number);

  // Return the current log file number.
  uint64_t LogNumber() const {
    return log_number_;
  }

  // Return the log file number for the log file that is currently
  // being compacted, or zero if there is no such log file.
  uint64_t PrevLogNumber() const {
    return prev_log_number_;
  }

  // Pick level and inputs for a new compaction.
  // Returns NULL if there is no compaction to be done.
  // Otherwise returns a pointer to a heap-allocated object that
  // describes the compaction.  Caller should delete the result.
  Compaction *PickCompaction();

  // Return a compaction object for compacting the range [begin,end] in
  // the specified level.  Returns NULL if there is nothing in that
  // level that overlaps the specified range.  Caller should delete
  // the result.
  Compaction *CompactRange(
    int level,
    const InternalKey *begin,
    const InternalKey *end);

  // Return the maximum overlapping data (in bytes) at next level for any
  // file at a level >= 1.
  int64_t MaxNextLevelOverlappingBytes();

  // Create an iterator that reads over the compaction inputs for "*c".
  // The caller should delete the iterator when no longer needed.
  Iterator *MakeInputIterator(Compaction *c);

  // Returns true iff some level needs a compaction.
  bool NeedsCompaction() const {
    Version *v = current_;
    return (v->compaction_score_ >= 1) || (v->file_to_compact_ != NULL);
  }

  // Add all files listed in any live version to *live.
  // May also mutate some internal state.
  void AddLiveFiles(std::set<uint64_t> *live);

  // Return the approximate offset in the database of the data for
  // "key" as of version "v".
  uint64_t ApproximateOffsetOf(Version *v, const InternalKey &key);

  // Return a human-readable short (single-line) summary of the number
  // of files per level.  Uses *scratch as backing store.
  struct LevelSummaryStorage {
    char buffer[100];
  };
  const char *LevelSummary(LevelSummaryStorage *scratch) const;

private:
  class Builder;

  friend class Compaction;
  friend class Version;

  bool ReuseManifest(const std::string &dscname, const std::string &dscbase);

  void Finalize(Version *v);

  void GetRange(const std::vector<FileMetaData *> &inputs,
    InternalKey *smallest,
    InternalKey *largest);

  void GetRange2(const std::vector<FileMetaData *> &inputs1,
    const std::vector<FileMetaData *> &inputs2,
    InternalKey *smallest,
    InternalKey *largest);

  void SetupOtherInputs(Compaction *c);

  // Save current contents to *log
  Status WriteSnapshot(log::Writer *log);

  void AppendVersion(Version *v);

  Env *const env_;
  const std::string dbname_;
  const Options *const options_;
  TableCache *const table_cache_;
  const InternalKeyComparator icmp_;
  uint64_t next_file_number_;
  uint64_t manifest_file_number_;
  uint64_t last_sequence_;
  uint64_t log_number_;
  uint64_t prev_log_number_;  // 0 or backing store for memtable being compacted

  // Opened lazily
  WritableFile *descriptor_file_;
  log::Writer *descriptor_log_;
  Version dummy_versions_;  // Head of circular doubly-linked list of versions.
  Version *current_;        // == dummy_versions_.prev_

  // Per-level key at which the next compaction at that level should start.
  // Either an empty string, or a valid InternalKey.
  std::string compact_pointer_[config::kNumLevels];

  // No copying allowed
  VersionSet(const VersionSet &);
  void operator=(const VersionSet &);
};

// A Compaction encapsulates information about a compaction.
class Compaction {
public:
  ~Compaction();

  // Return the level that is being compacted.  Inputs from "level"
  // and "level+1" will be merged to produce a set of "level+1" files.
  int level() const {
    return level_;
  }

  // Return the object that holds the edits to the descriptor done
  // by this compaction.
  VersionEdit *edit() {
    return &edit_;
  }

  // "which" must be either 0 or 1
  int num_input_files(int which) const {
    return (int)inputs_[which].size();
  }

  // Return the ith input file at "level()+which" ("which" must be 0 or 1).
  FileMetaData *input(int which, int i) const {
    return inputs_[which][i];
  }

  // Maximum size of files to build during this compaction.
  uint64_t MaxOutputFileSize() const {
    return max_output_file_size_;
  }

  // Is this a trivial compaction that can be implemented by just
  // moving a single input file to the next level (no merging or splitting)
  bool IsTrivialMove() const;

  // Add all inputs to this compaction as delete operations to *edit.
  void AddInputDeletions(VersionEdit *edit);

  // Returns true if the information we have available guarantees that
  // the compaction is producing data in "level+1" for which no data exists
  // in levels greater than "level+1".
  bool IsBaseLevelForKey(const Slice &user_key);

  // Returns true iff we should stop building the current output
  // before processing "internal_key".
  bool ShouldStopBefore(const Slice &internal_key);

  // Release the input version for the compaction, once the compaction
  // is successful.
  void ReleaseInputs();

private:
  friend class Version;
  friend class VersionSet;

  Compaction(const Options *options, int level);

  int level_;
  uint64_t max_output_file_size_;
  Version *input_version_;
  VersionEdit edit_;

  // Each compaction reads inputs from "level_" and "level_+1"
  std::vector<FileMetaData *> inputs_[2];      // The two sets of inputs

  // State used to check for number of of overlapping grandparent files
  // (parent == level_ + 1, grandparent == level_ + 2)
  std::vector<FileMetaData *> grandparents_;
  size_t grandparent_index_;  // Index in grandparent_starts_
  bool seen_key_;             // Some output key has been seen
  int64_t overlapped_bytes_;  // Bytes of overlap between current output
  // and grandparent files

  // State for implementing IsBaseLevelForKey

  // level_ptrs_ holds indices into input_version_->levels_: our state
  // is that we are positioned at one of the file ranges for each
  // higher level than the ones involved in this compaction (i.e. for
  // all L >= level_ + 2).
  size_t level_ptrs_[config::kNumLevels];
};

// ----------------------------------------------------------------------------
// - db/write_batch_internal.h
// ----------------------------------------------------------------------------

// WriteBatchInternal provides static methods for manipulating a
// WriteBatch that we don't want in the public WriteBatch interface.
class WriteBatchInternal {
public:
  // Return the number of entries in the batch.
  static int Count(const WriteBatch *batch);

  // Set the count for the number of entries in the batch.
  static void SetCount(WriteBatch *batch, int n);

  // Return the sequence number for the start of this batch.
  static SequenceNumber Sequence(const WriteBatch *batch);

  // Store the specified number as the sequence number for the start of
  // this batch.
  static void SetSequence(WriteBatch *batch, SequenceNumber seq);

  static Slice Contents(const WriteBatch *batch) {
    return Slice(batch->rep_);
  }

  static size_t ByteSize(const WriteBatch *batch) {
    return batch->rep_.size();
  }

  static void SetContents(WriteBatch *batch, const Slice &contents);

  static Status InsertInto(const WriteBatch *batch, MemTable *memtable);

  static void Append(WriteBatch *dst, const WriteBatch *src);
};

// ----------------------------------------------------------------------------
// - db/db_impl.h
// ----------------------------------------------------------------------------

class DBImpl: public DB {
public:
  DBImpl(const Options &options, const std::string &dbname);
  virtual ~DBImpl();

  // Implementations of the DB interface
  virtual Status Put(const WriteOptions &, const Slice &key, const Slice &value);
  virtual Status Delete(const WriteOptions &, const Slice &key);
  virtual Status Write(const WriteOptions &options, WriteBatch *updates);
  virtual Status Get(const ReadOptions &options,
    const Slice &key,
    std::string *value);
  virtual Iterator *NewIterator(const ReadOptions &);
  virtual const Snapshot *GetSnapshot();
  virtual void ReleaseSnapshot(const Snapshot *snapshot);
  virtual bool GetProperty(const Slice &property, std::string *value);
  virtual void GetApproximateSizes(const Range *range, int n, uint64_t *sizes);
  virtual void CompactRange(const Slice *begin, const Slice *end);
  // Set the suspend flag, which tells the database not to schedule background work until resume
  // Waits for any currently executing BG work to complete before returning
  virtual void SuspendCompaction();
  // Clears the suspend flag, so that the database can schedule background work
  virtual void ResumeCompaction();


  // Extra methods (for testing) that are not in the public DB interface

  // Compact any files in the named level that overlap [*begin,*end]
  void TEST_CompactRange(int level, const Slice *begin, const Slice *end);

  // Force current memtable contents to be compacted.
  Status TEST_CompactMemTable();

  // Return an internal iterator over the current state of the database.
  // The keys of this iterator are internal keys (see format.h).
  // The returned iterator should be deleted when no longer needed.
  Iterator *TEST_NewInternalIterator();

  // Return the maximum overlapping data (in bytes) at next level for any
  // file at a level >= 1.
  int64_t TEST_MaxNextLevelOverlappingBytes();

  // Record a sample of bytes read at the specified internal key.
  // Samples are taken approximately once every config::kReadBytesPeriod
  // bytes.
  void RecordReadSample(Slice key);

private:
  friend class DB;
  struct CompactionState;
  struct Writer;

  Iterator *NewInternalIterator(
    const ReadOptions &,
    SequenceNumber *latest_snapshot,
    uint32_t *seed);

  Status NewDB();

  // Recover the descriptor from persistent storage.  May do a significant
  // amount of work to recover recently logged updates.  Any changes to
  // be made to the descriptor are added to *edit.
  Status Recover(VersionEdit *edit, bool *save_manifest)
    EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  void MaybeIgnoreError(Status *s) const;

  // Delete any unneeded files and stale in-memory entries.
  void DeleteObsoleteFiles();

  // Compact the in-memory write buffer to disk.  Switches to a new
  // log-file/memtable and writes a new descriptor iff successful.
  // Errors are recorded in bg_error_.
  void CompactMemTable() EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  Status RecoverLogFile(uint64_t log_number, bool last_log, bool *save_manifest,
    VersionEdit *edit, SequenceNumber *max_sequence)
    EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  Status WriteLevel0Table(MemTable *mem, VersionEdit *edit, Version *base)
    EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  Status MakeRoomForWrite(bool force /* compact even if there is room? */)
    EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  WriteBatch *BuildBatchGroup(Writer **last_writer);

  void RecordBackgroundError(const Status &s);

  void MaybeScheduleCompaction() EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  static void BGWork(void *db);
  void BackgroundCall();
  void  BackgroundCompaction() EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  void CleanupCompaction(CompactionState *compact)
    EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  Status DoCompactionWork(CompactionState *compact)
    EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  Status OpenCompactionOutputFile(CompactionState *compact);
  Status FinishCompactionOutputFile(CompactionState *compact, Iterator *input);
  Status InstallCompactionResults(CompactionState *compact)
    EXCLUSIVE_LOCKS_REQUIRED(mutex_);

  // Constant after construction
  Env *const env_;
  const InternalKeyComparator internal_comparator_;
  const InternalFilterPolicy internal_filter_policy_;
  const Options options_;  // options_.comparator == &internal_comparator_
  bool owns_info_log_;
  bool owns_cache_;
  const std::string dbname_;

  // table_cache_ provides its own synchronization
  TableCache *table_cache_;

  // Lock over the persistent DB state.  Non-NULL iff successfully acquired.
  FileLock *db_lock_;

  // State below is protected by mutex_
  port::Mutex mutex_;
  port::AtomicPointer shutting_down_;
  port::CondVar bg_cv_;          // Signalled when background work finishes
  MemTable *mem_;
  MemTable *imm_;                // Memtable being compacted
  port::AtomicPointer has_imm_;  // So bg thread can detect non-NULL imm_
  WritableFile *logfile_;
  uint64_t logfile_number_;
  log::Writer *log_;
  uint32_t seed_;                // For sampling.

  // Queue of writers.
  std::deque<Writer *> writers_;
  WriteBatch *tmp_batch_;

  SnapshotList snapshots_;

  // Set of table files to protect from deletion because they are
  // part of ongoing compactions.
  std::set<uint64_t> pending_outputs_;

  // Has a background compaction been scheduled or is running?
  bool bg_compaction_scheduled_;

  // Has anyone issued a request to suspend background work?
  port::AtomicPointer suspending_compaction_;

  // Information for a manual compaction
  struct ManualCompaction {
    int level;
    bool done;
    const InternalKey *begin;   // NULL means beginning of key range
    const InternalKey *end;     // NULL means end of key range
    InternalKey tmp_storage;    // Used to keep track of compaction progress
  };
  ManualCompaction *manual_compaction_;

  VersionSet *versions_;

  // Have we encountered a background error in paranoid mode?
  Status bg_error_;

  // Per level compaction stats.  stats_[level] stores the stats for
  // compactions that produced data for the specified "level".
  struct CompactionStats {
    int64_t micros;
    int64_t bytes_read;
    int64_t bytes_written;

    CompactionStats(): micros(0), bytes_read(0), bytes_written(0) { }

    void Add(const CompactionStats &c) {
      this->micros += c.micros;
      this->bytes_read += c.bytes_read;
      this->bytes_written += c.bytes_written;
    }
  };
  CompactionStats stats_[config::kNumLevels];

  // No copying allowed
  DBImpl(const DBImpl &);
  void operator=(const DBImpl &);

  const Comparator *user_comparator() const {
    return internal_comparator_.user_comparator();
  }
};

// Sanitize db options.  The caller should delete result.info_log if
// it is not equal to src.info_log.
extern Options SanitizeOptions(
  const std::string &db,
  const InternalKeyComparator *icmp,
  const InternalFilterPolicy *ipolicy,
  const Options &src);

}  // namespace leveldb
