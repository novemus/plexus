CC = g++
RM = rm
CXXFLAGS = -std=c++17 -Wall -g
LDFLAGS = -lssl -lcrypto -lpthread -lboost_thread -lboost_system -lboost_program_options -lboost_unit_test_framework

SRC_DIR = .
OBJ_DIR = obj

DEP_SRC_DIR = ..
DEP_OBJ_DIR = ../obj

SRC = utils_tests.cpp
OBJ = $(SRC:%.cpp=$(OBJ_DIR)/%.o)
DEP_OBJ = ../obj/utils.o

all: tests

tests: $(DEP_OBJ) $(OBJ)
	$(CC) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CC) $(CXXFLAGS) -o $@ -c $<

$(DEP_OBJ_DIR)/%.o: $(DEP_SRC_DIR)/%.cpp
	$(CC) $(CXXFLAGS) -o $@ -c $<

clean:
	$(RM) $(OBJ) tests
