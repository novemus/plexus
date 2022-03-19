CC = g++
RM = rm
CXXFLAGS = -std=c++17 -Wall -g
LDFLAGS = -lssl -lcrypto -lpthread -lboost_thread -lboost_system -lboost_program_options

SRC_DIR = .
OBJ_DIR = obj

SRC = utils.cpp udp.cpp stun.cpp ssl.cpp log.cpp exec.cpp email.cpp main.cpp
OBJ = $(SRC:%.cpp=$(OBJ_DIR)/%.o)

all: plexus

plexus: $(OBJ)
	$(CC) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CC) $(CXXFLAGS) -o $@ -c $<

clean:
	$(RM) $(OBJ) plexus
