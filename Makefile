CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -g
LDFLAGS = -lpcap -lncurses
TARGET  = my_sniffer

# 基础模块（第一周逐步添加）
SRCS    = main.c
OBJS    = $(SRCS:.c=.o)

# 后续模块取消注释即可加入编译
# SRCS += capture.c filter.c pcap_io.c ring_buffer.c stats.c
# SRCS += protocol.c tcp_reasm.c tls_parser.c ui.c

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c common.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET) $(OBJS)

run: $(TARGET)
	sudo ./$(TARGET)
