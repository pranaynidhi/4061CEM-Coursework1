CC = gcc
CFLAGS = -Iinclude
LDFLAGS = -lpcap
SRCS = src/main.c src/packet_capture.c src/detection.c src/logging.c
OBJS = $(SRCS:.c=.o)
EXEC = ids

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

clean:
	rm -f $(OBJS) $(EXEC)
