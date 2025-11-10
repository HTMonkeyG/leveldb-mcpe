// Copyright (c) 2011 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.

#ifndef STORAGE_LEVELDB_BACKEND_H_
#define STORAGE_LEVELDB_BACKEND_H_

#include <string.h>

#if defined(_MSC_VER)
#include <codecvt>
#include <string>
#include <fstream>
#endif

#include "leveldb_config.h"

// Include the appropriate platform specific file below. If you are
// porting to a new platform, see "leveldb_impl_example.h" for documentation
// of what the new leveldb_impl_<platform>.h file must provide.
#if defined(WIN32)
#include "leveldb_impl_win32.h"
#endif

#endif  // STORAGE_LEVELDB_BACKEND_H_
