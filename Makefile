CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = -lbcrypt -ljson-c

TARGET = password_manager
SRC = password_manager.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET) 