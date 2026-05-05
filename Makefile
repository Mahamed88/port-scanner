# Makefile - Build rules for the port scanner

CXX      = g++
CXXFLAGS = -std=c++17 -pthread -Wall
TARGET   = scanner
SRCS     = main.cpp scanner.cpp threadpool.cpp
OBJS     = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	g++ $(CXXFLAGS) -o $(TARGET) $(OBJS)

%.o: %.cpp
	g++ $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)