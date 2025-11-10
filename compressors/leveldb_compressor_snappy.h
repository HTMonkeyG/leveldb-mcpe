#pragma once

#include "leveldb_config.h"
#include "leveldb_internal.h"

#ifdef LEVELDB_SNAPPY

namespace leveldb {

class LEVELDB_DLLX SnappyCompressor : public Compressor  {
public:

  static const char SERIALIZE_ID = 1;
      
  virtual ~SnappyCompressor() { }

  SnappyCompressor()
    : Compressor(SERIALIZE_ID) { }

  virtual void compressImpl(
    const char* input,
    size_t length,
    std::string& output
  ) const override;

  virtual bool decompress(
    const char* input,
    size_t length,
    std::string& output
  ) const override;
};

}

#endif
