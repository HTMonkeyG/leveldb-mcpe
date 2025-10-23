// Copyright (c) 2011 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.

#ifndef STORAGE_LEVELDB_INCLUDE_LEVELDB_INTERNAL_H_
#define STORAGE_LEVELDB_INCLUDE_LEVELDB_INTERNAL_H_

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

#include "leveldb/leveldb_config.h"
#include "leveldb/leveldb.h"

namespace leveldb {

// Update Makefile if you change these
static const int kMajorVersion = 1;
static const int kMinorVersion = 20;

// Type definitions.
class DLLX BlockBuilder;
class DLLX BlockHandle;
class DLLX Cache;
class DLLX Comparator;
class DLLX Compressor;
class DLLX DecompressAllocator;
class DLLX Env;
class DLLX FileLock;
class DLLX FilterPolicy;
class DLLX Footer;
class DLLX Iterator;
class DLLX Logger;
class DLLX RandomAccessFile;
class DLLX SequentialFile;
class DLLX Slice;
class DLLX Status;
class DLLX TableBuilder;
class DLLX TableCache;
class DLLX WriteBatch;
class DLLX WritableFile;

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

extern DLLX Cache *NewLRUCache(size_t capacity);

class DLLX Cache {
public:

  Cache() { }

  // Destroys all existing entries by calling the "deleter"
  // function that was passed to the constructor.
  virtual ~Cache();

  // Opaque handle to an entry stored in the cache.
  struct DLLX Handle { };

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
    void* value,
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
  virtual void* Value(Handle *handle) = 0;

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
  virtual void Prune() {}

  // Return an estimate of the combined charges of all elements stored in the
  // cache.
  virtual size_t TotalCharge() const = 0;

private:
  void LRU_Remove(Handle *e);
  void LRU_Append(Handle *e);
  void Unref(Handle *e);

  struct DLLX Rep;
  Rep* rep_;

  // No copying allowed
  Cache(const Cache&);
  void operator=(const Cache&);
};

// ----------------------------------------------------------------------------
// - compressor.h
// ----------------------------------------------------------------------------

class DLLX Compressor {
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
    const char* input,
    size_t length,
    std::string& output
  ) {
    compressImpl(input, length, output);

    inputBytes += length;
    compressedBytes += output.length();
  }

  void compress(const std::string& in, std::string& out) {
    compress(in.data(), in.length(), out);
  }

  virtual void compressImpl(
    const char* input,
    size_t length,
    std::string& output
  ) const = 0;

  virtual bool decompress(
    const char* input,
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

class DLLX WriteBatch {
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
  class DLLX Handler {
  public:
    virtual ~Handler();
    virtual void Put(const Slice &key, const Slice &value) = 0;
    virtual void Delete(const Slice &key) = 0;
  };
  Status Iterate(Handler* handler) const;

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
class DLLX Table {
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
  struct DLLX Rep;
  Rep *rep_;

  explicit Table(Rep *rep) { rep_ = rep; }
  static Iterator *BlockReader(void *, const ReadOptions &, const Slice &);

  // Calls (*handle_result)(arg, ...) with the entry found after a call
  // to Seek(key).  May not make such a call if filter policy says
  // that key is not present.
  friend class DLLX TableCache;
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

class DLLX TableBuilder {
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
  bool ok() const { return status().ok(); }
  void WriteBlock(BlockBuilder *block, BlockHandle *handle);
  void WriteRawBlock(const Slice &data, Compressor *compressor, BlockHandle *handle);

  struct DLLX Rep;
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

class DLLX FilterPolicy {
 public:
  virtual ~FilterPolicy();

  // Return the name of this policy.  Note that if the filter encoding
  // changes in an incompatible way, the name returned by this method
  // must be changed.  Otherwise, old incompatible filters may be
  // passed to methods of this type.
  virtual const char* Name() const = 0;

  // keys[0,n-1] contains a list of keys (potentially with duplicates)
  // that are ordered according to the user supplied comparator.
  // Append a filter that summarizes keys[0,n-1] to *dst.
  //
  // Warning: do not change the initial contents of *dst.  Instead,
  // append the newly constructed filter to *dst.
  virtual void CreateFilter(const Slice* keys, int n, std::string* dst)
      const = 0;

  // "filter" contains the data appended by a preceding call to
  // CreateFilter() on this class.  This method must return true if
  // the key was in the list of keys passed to CreateFilter().
  // This method may return true or false if the key was not on the
  // list, but it should aim to return false with a high probability.
  virtual bool KeyMayMatch(const Slice& key, const Slice& filter) const = 0;
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
extern DLLX const FilterPolicy *NewBloomFilterPolicy(int bits_per_key);

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

class DLLX Env {
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
class DLLX SequentialFile {
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
class DLLX RandomAccessFile {
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
class DLLX WritableFile {
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

// An interface for writing log messages.
class DLLX Logger {
 public:
  Logger() { }
  virtual ~Logger();

  // Write an entry to the log file with the specified format.
  virtual void Logv(
    const char *format,
    va_list ap
  ) = 0;

 private:
  // No copying allowed
  Logger(
    const Logger &);
  void operator=(
    const Logger &);
};


// Identifies a locked file.
class DLLX FileLock {
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
extern void Log(Logger* info_log, const char* format, ...)
#if defined(__GNUC__) || defined(__clang__)
  __attribute__((__format__ (__printf__, 2, 3)))
#endif
  ;

// A utility routine: write "data" to the named file.
extern Status WriteStringToFile(
  Env *env,
  const Slice &data,
  const std::string &fname);

// A utility routine: read contents of named file into *data
extern Status ReadFileToString(Env* env, const std::string& fname,
                               std::string* data);

// An implementation of Env that forwards all calls to another Env.
// May be useful to clients who wish to override just part of the
// functionality of another Env.
class DLLX EnvWrapper: public Env {
public:
  // Initialize an EnvWrapper that delegates all calls to *t
  explicit EnvWrapper(Env* t) : target_(t) { }
  virtual ~EnvWrapper();

  // Return the target to which this Env forwards all calls
  Env* target() const { return target_; }

  // The following text is boilerplate that forwards all methods to target()
  Status NewSequentialFile(const std::string& f, SequentialFile** r) {
    return target_->NewSequentialFile(f, r);
  }
  Status NewRandomAccessFile(const std::string& f, RandomAccessFile** r) {
    return target_->NewRandomAccessFile(f, r);
  }
  Status NewWritableFile(const std::string& f, WritableFile** r) {
    return target_->NewWritableFile(f, r);
  }
  Status NewAppendableFile(const std::string& f, WritableFile** r) {
    return target_->NewAppendableFile(f, r);
  }
  bool FileExists(const std::string& f) { return target_->FileExists(f); }
  Status GetChildren(const std::string& dir, std::vector<std::string>* r) {
    return target_->GetChildren(dir, r);
  }
  Status DeleteFile(const std::string& f) { return target_->DeleteFile(f); }
  Status CreateDir(const std::string& d) { return target_->CreateDir(d); }
  Status DeleteDir(const std::string& d) { return target_->DeleteDir(d); }
  Status GetFileSize(const std::string& f, uint64_t* s) {
    return target_->GetFileSize(f, s);
  }
  Status RenameFile(const std::string& s, const std::string& t) {
    return target_->RenameFile(s, t);
  }
  Status LockFile(const std::string& f, FileLock** l) {
    return target_->LockFile(f, l);
  }
  Status UnlockFile(FileLock* l) { return target_->UnlockFile(l); }
  void Schedule(void (*f)(void*), void* a) {
    return target_->Schedule(f, a);
  }
  void StartThread(void (*f)(void*), void* a) {
    return target_->StartThread(f, a);
  }
  virtual Status GetTestDirectory(std::string* path) {
    return target_->GetTestDirectory(path);
  }
  virtual Status NewLogger(const std::string& fname, Logger** result) {
    return target_->NewLogger(fname, result);
  }
  uint64_t NowMicros() {
    return target_->NowMicros();
  }
  void SleepForMicroseconds(int micros) {
    target_->SleepForMicroseconds(micros);
  }
private:
  Env* target_;
};

// ----------------------------------------------------------------------------
// - decompress_allocator.h
// ----------------------------------------------------------------------------

class DLLX DecompressAllocator {
public:
  virtual ~DecompressAllocator();

  virtual std::string get();
  virtual void release(std::string&& string);

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
Status DumpFile(Env* env, const std::string& fname, WritableFile* dst);

// ----------------------------------------------------------------------------
// - comparator.h
// ----------------------------------------------------------------------------

// A Comparator object provides a total order across slices that are
// used as keys in an sstable or a database.  A Comparator implementation
// must be thread-safe since leveldb may invoke its methods concurrently
// from multiple threads.
class DLLX Comparator {
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

}  // namespace leveldb

#endif  // STORAGE_LEVELDB_INCLUDE_LEVELDB_INTERNAL_H_
