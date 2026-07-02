CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -g
LDFLAGS = -lpcap -lncurses
TARGET  = my_sniffer

# 基础模块（逐步添加）
SRCS    = main.c capture.c filter.c protocol.c stats.c
OBJS    = $(SRCS:.c=.o)

# 后续模块取消注释即可加入编译
# SRCS += pcap_io.c ring_buffer.c
# SRCS += tcp_reasm.c tls_parser.c ui.c

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c common.h protocol.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET) $(OBJS)

run: $(TARGET)
	sudo ./$(TARGET)
