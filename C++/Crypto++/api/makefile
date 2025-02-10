CXX = g++
CXXFLAGS = -std=c++11 -Wall
LIBS = -lcryptopp

SRCS = main.cpp
OBJS = $(SRCS:.cpp=.o)
EXEC = main

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CXX) $(CXXFLAGS) $(OBJS) -o $(EXEC) $(LIBS)

.cpp.o:
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	$(RM) $(OBJS) $(EXEC)
