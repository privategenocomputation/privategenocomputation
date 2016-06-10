# Makefile for SEAL examples
BIN_DIR=../bin
INCLUDE_DIR=../SEAL
CXXFLAGS=-Wall -Wno-unused-function -std=c++11 -O3 -I$(INCLUDE_DIR)
SRCS=THELC.cpp
OBJS=$(SRCS:.cpp=.o)
THERUN=$(BIN_DIR)/THELC.exe

.PHONY: all clean

all: $(THERUN)

$(THERUN): $(OBJS)
	$(CXX) $(CXXFLAGS) $(OBJS) -L$(BIN_DIR) -lseal -o $(THERUN)

clean:
	-rm -f $(OBJS) $(SEALRUN)
