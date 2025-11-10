MAKEFLAGS += -s -j

DIST_DIR = ./dist
SRC_DIR = .

AR = ar
CXX = g++
CC = gcc

SRC_DIRS = $(SRC_DIR) $(wildcard $(SRC_DIR)/*/)

CFLAGS = -O3 -std=c++11 -g -Wall -Wformat -I. -I./backends -I./compressors -DWIN32 -DLEVELDB_PLATFORM_WINDOWS -fno-rtti
# CFLAGS += -DLEVELDB_DLLX=
CFLAGS += -Wno-unused-variable -Wno-attributes -Wno-sign-compare

CPP_SRC = ./leveldb.cc\
					./leveldb_c.cc\
					./leveldb_table.cc\
					./leveldb_utils.cc\
					./leveldb_crc32c.cc\
					./leveldb_env.cc\
					./backends/leveldb_impl_posix_sse.cc\
					./backends/leveldb_impl_win32.cc\
					#./compressors/leveldb_compressor_zlib.cc
CPP_OBJ = $(addprefix $(DIST_DIR)/, $(notdir $(CPP_SRC:.cc=.o)))

TARGET = leveldb.lib
BIN_TARGET = $(DIST_DIR)/$(TARGET)

vpath %.cc $(SRC_DIRS)

$(BIN_TARGET): $(CPP_OBJ)
	@echo Linking ...
	@$(AR) rcs $@ $^
#	@$(CXX) $^ -shared -o $@ -L. -lz
	@echo Done.

$(DIST_DIR)/%.o: %.cc
	@echo Compiling file "$<" ...
	@$(CXX) $(CFLAGS) -c $< -o $@

clean:
	-@del dist\*.a
	-@del dist\*.o