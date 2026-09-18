CXX      ?= clang++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Wpedantic -Iinclude
LDFLAGS  ?=
LIBS     ?=

SRC := src/main.cpp \
       src/utils.cpp \
       src/speed_tracker.cpp \
       src/activity_monitor.cpp \
       src/threat_detector.cpp

OBJ := $(SRC:src/%.cpp=build/%.o)
BIN := network_track

.PHONY: all clean run

all: $(BIN)

$(BIN): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

build/%.o: src/%.cpp | build
	$(CXX) $(CXXFLAGS) -c -o $@ $<

build:
	mkdir -p build

run: $(BIN)
	./$(BIN)

clean:
	rm -rf build $(BIN)
