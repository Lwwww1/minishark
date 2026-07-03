CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -g -Iinclude
LDFLAGS = -lpcap -lncurses
TARGET  = my_sniffer

# 源文件目录
SRCDIR  = src
SRCS    = $(SRCDIR)/main.c \
          $(SRCDIR)/capture.c \
          $(SRCDIR)/filter.c \
          $(SRCDIR)/protocol.c \
          $(SRCDIR)/stats.c \
          $(SRCDIR)/pcap_io.c
OBJS    = $(SRCS:.c=.o)

# 后续模块
# SRCS += $(SRCDIR)/pcap_io.c $(SRCDIR)/ring_buffer.c
# SRCS += $(SRCDIR)/tcp_reasm.c $(SRCDIR)/tls_parser.c $(SRCDIR)/ui.c

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(SRCDIR)/%.o: $(SRCDIR)/%.c include/common.h include/protocol.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET) $(SRCDIR)/*.o

run: $(TARGET)
	sudo ./$(TARGET)
