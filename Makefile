CXX=g++
CXXFLAGS=-std=c++17 -Wall -Wextra -O2
LDLIBS=-lpcap
TARGET=tls-block
SRCS=main.cpp hdr.cpp
OBJS=$(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f $(TARGET) $(OBJS)

.PHONY: all clean
