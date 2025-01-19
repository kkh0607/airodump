CC = g++
CFLAGS = -std=c++17 -Wall -pthread -g
TARGET = airodump
SRC = main.cpp airodump.cpp
HDR = airodump.h

all: $(TARGET)

$(TARGET): $(SRC) $(HDR)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) -lpcap

clean:
	rm -f $(TARGET)

