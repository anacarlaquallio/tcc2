CXX = g++
CXXFLAGS = -std=c++20

BOTAN_CONFIG = botan config

# Obter as flags de compilação do Botan
CXXFLAGS += $(shell $(BOTAN_CONFIG) cflags) -I/usr/local/include/botan-3

# Obter as bibliotecas necessárias para vinculação
LIBS = $(shell $(BOTAN_CONFIG) libs) -lbotan-3

all: main

main: main.o
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LIBS)

main.o: main.cpp
	$(CXX) $(CXXFLAGS) -c $<

clean:
	rm -f *.o main