CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -g -Iinclude
LDFLAGS = -lpcap -lncurses
TARGET  = my_sniffer
TEST_TARGET = test_protocol

# 源文件目录
SRCDIR  = src
SRCS    = $(SRCDIR)/main.c \
          $(SRCDIR)/capture.c \
          $(SRCDIR)/filter.c \
          $(SRCDIR)/protocol.c \
          $(SRCDIR)/stats.c \
          $(SRCDIR)/pcap_io.c
OBJS    = $(SRCS:.c=.o)

# 测试源文件
TESTDIR = tests
TEST_SRCS = $(TESTDIR)/test_protocol.c $(SRCDIR)/protocol.c

# 后续模块
# SRCS += $(SRCDIR)/pcap_io.c $(SRCDIR)/ring_buffer.c
# SRCS += $(SRCDIR)/tcp_reasm.c $(SRCDIR)/tls_parser.c $(SRCDIR)/ui.c

.PHONY: all clean run test test-verbose

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(SRCDIR)/%.o: $(SRCDIR)/%.c include/common.h include/protocol.h
	$(CC) $(CFLAGS) -c -o $@ $<

# 协议解析测试（不需要 pcap/ncurses）
$(TESTDIR)/$(TEST_TARGET): $(TEST_SRCS) include/protocol.h include/common.h
	$(CC) $(CFLAGS) -o $@ $(TEST_SRCS)

test: $(TESTDIR)/$(TEST_TARGET)
	./$(TESTDIR)/$(TEST_TARGET)

test-verbose: $(TESTDIR)/$(TEST_TARGET)
	$(CC) $(CFLAGS) -DVERBOSE -o $(TESTDIR)/$(TEST_TARGET) $(TEST_SRCS)
	./$(TESTDIR)/$(TEST_TARGET)

clean:
	rm -f $(TARGET) $(SRCDIR)/*.o
	rm -f $(TESTDIR)/$(TEST_TARGET) $(TESTDIR)/*.o

run: $(TARGET)
	sudo ./$(TARGET)
