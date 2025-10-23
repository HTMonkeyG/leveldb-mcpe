MAKEFLAGS += -s -j

DIST_DIR = ./dist
SRC_DIR = .

AR = ar
CXX = g++
CC = gcc

SRC_DIRS = $(SRC_DIR) $(wildcard $(SRC_DIR)/*/)

CFLAGS = -O3 -std=c++11 -g -Wall -Wformat -I. -I./include -DWIN32 -DDLLX= -DLEVELDB_PLATFORM_WINDOWS -fno-rtti
CFLAGS += -Wno-unused-variable -Wno-attributes -Wno-sign-compare

CPP_SRC = ./leveldb.cc ./leveldb_c.cc ./leveldb_table.cc ./leveldb_utils.cc ./leveldb_crc32c.cc
CPP_SRC += ./port/port_posix_sse.cc ./port/port_win.cc ./util/env_win.cc ./util/win_logger.cc
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