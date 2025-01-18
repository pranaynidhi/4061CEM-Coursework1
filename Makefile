CC = gcc
CFLAGS = -Iinclude
LDFLAGS = -lpcap -lmaxminddb -lncurses
SRCS = src/main.c src/packet_capture.c src/detection.c src/logging.c src/monitoring.c
OBJS = $(SRCS:.c=.o)
EXEC = ids

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

clean:
	find . -name "*.o" -type f -delete
	rm -f $(EXEC)
