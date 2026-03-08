GCC ?= gcc
CXX ?= g++

PLUGIN_NAME := callsite_plugin
TARGET := $(PLUGIN_NAME).so
SRC := src/plugin.cpp

GCC_PLUGIN_DIR := $(shell $(GCC) -print-file-name=plugin)
GCC_PLUGIN_INC := $(GCC_PLUGIN_DIR)/include

CXXFLAGS := -O0 -g -fPIC -shared -std=gnu++17 \
            -I$(GCC_PLUGIN_INC) \
            -Wall -Wextra

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f $(TARGET)
