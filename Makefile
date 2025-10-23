MAKEFLAGS += -s -j

DIST_DIR = ./dist
SRC_DIR = .

AR = ar
CXX = g++
CC = gcc

SRC_DIRS = $(SRC_DIR) $(wildcard $(SRC_DIR)/*/)

CFLAGS = -O3 -std=c++11 -g -Wall -Wformat -I. -I./include -DWIN32 -DDLLX= -DLEVELDB_PLATFORM_WINDOWS -fno-rtti
CFLAGS += -Wno-unused-variable -Wno-attributes -Wno-sign-compare

CPP_SRC = db/builder.cc db/c.cc db/db_impl.cc db/db_iter.cc db/dbformat.cc db/filename.cc db/log_reader.cc db/log_writer.cc db/memtable.cc db/repair.cc db/table_cache.cc db/version_edit.cc db/version_set.cc db/write_batch.cc db/zlib_compressor.cc
CPP_SRC += table/block.cc table/block_builder.cc table/filter_block.cc table/format.cc table/iterator.cc table/merger.cc table/table.cc table/table_builder.cc table/two_level_iterator.cc
CPP_SRC += util/arena.cc util/bloom.cc util/cache.cc util/coding.cc util/comparator.cc util/crc32c.cc util/env.cc util/filter_policy.cc util/hash.cc util/histogram.cc util/logging.cc util/options.cc util/status.cc
CPP_SRC += port/port_posix_sse.cc port/port_win.cc util/env_win.cc util/win_logger.cc
CPP_OBJ = $(addprefix $(DIST_DIR)/, $(notdir $(CPP_SRC:.cc=.o)))

TARGET = libleveldb.a
BIN_TARGET = $(DIST_DIR)/$(TARGET)

vpath %.cc $(SRC_DIRS)

$(BIN_TARGET): $(CPP_OBJ)
	@echo Linking ...
	@$(AR) rcs $@ $^
	@echo Done.

$(DIST_DIR)/%.o: %.cc
	@echo Compiling file "$<" ...
	@$(CXX) $(CFLAGS) -c $< -o $@ -fvisibility=hidden

clean:
	-@del dist\*.a
	-@del dist\*.o