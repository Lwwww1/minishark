CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -g -Iinclude
LDFLAGS = -lpcap -lncurses -lpthread
TARGET  = my_sniffer

# 源文件目录
SRCDIR  = src
SRCS    = $(SRCDIR)/main.c \
          $(SRCDIR)/capture.c \
          $(SRCDIR)/filter.c \
          $(SRCDIR)/protocol.c \
          $(SRCDIR)/stats.c \
          $(SRCDIR)/pcap_io.c \
          $(SRCDIR)/ring_buffer.c \
          $(SRCDIR)/tcp_reasm.c \
          $(SRCDIR)/ip_reasm.c \
          $(SRCDIR)/http_extract.c
OBJS    = $(SRCS:.c=.o)

# 测试源文件
TESTDIR = tests
TEST_SRCS       = $(TESTDIR)/test_protocol.c $(SRCDIR)/protocol.c
TEST_REASM_SRC  = $(TESTDIR)/test_tcp_reasm.c $(SRCDIR)/tcp_reasm.c
TEST_IPREASM_SRC= $(TESTDIR)/test_ip_reasm.c $(SRCDIR)/ip_reasm.c $(SRCDIR)/tcp_reasm.c
TEST_HTTP_SRC   = $(TESTDIR)/test_http_extract.c $(SRCDIR)/http_extract.c

.PHONY: all clean run test test-verbose test-reasm test-reasm-verbose \
        test-ipreasm test-ipreasm-verbose test-http test-http-verbose

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(SRCDIR)/%.o: $(SRCDIR)/%.c include/common.h include/protocol.h include/tcp_reasm.h include/ip_reasm.h include/http_extract.h
	$(CC) $(CFLAGS) -c -o $@ $<

# ============================================================
#  协议解析测试
# ============================================================

$(TESTDIR)/test_protocol: $(TEST_SRCS) include/protocol.h include/common.h
	$(CC) $(CFLAGS) -o $@ $(TEST_SRCS)

test: $(TESTDIR)/test_protocol
	./$(TESTDIR)/test_protocol

test-verbose: $(TESTDIR)/test_protocol
	$(CC) $(CFLAGS) -DVERBOSE -o $(TESTDIR)/test_protocol $(TEST_SRCS)
	./$(TESTDIR)/test_protocol

# ============================================================
#  TCP 重组测试
# ============================================================

TEST_REASM_TARGET = test_tcp_reasm

$(TESTDIR)/$(TEST_REASM_TARGET): $(TEST_REASM_SRC) include/tcp_reasm.h include/protocol.h include/common.h
	$(CC) $(CFLAGS) -o $@ $(TEST_REASM_SRC)

test-reasm: $(TESTDIR)/$(TEST_REASM_TARGET)
	./$(TESTDIR)/$(TEST_REASM_TARGET)

test-reasm-verbose: $(TESTDIR)/$(TEST_REASM_TARGET)
	$(CC) $(CFLAGS) -DVERBOSE -o $(TESTDIR)/$(TEST_REASM_TARGET) $(TEST_REASM_SRC)
	./$(TESTDIR)/$(TEST_REASM_TARGET)

# ============================================================
#  IP 分片重组测试
# ============================================================

TEST_IPREASM_TARGET = test_ip_reasm

$(TESTDIR)/$(TEST_IPREASM_TARGET): $(TEST_IPREASM_SRC) include/ip_reasm.h include/tcp_reasm.h include/protocol.h include/common.h
	$(CC) $(CFLAGS) -o $@ $(TEST_IPREASM_SRC)

test-ipreasm: $(TESTDIR)/$(TEST_IPREASM_TARGET)
	./$(TESTDIR)/$(TEST_IPREASM_TARGET)

test-ipreasm-verbose: $(TESTDIR)/$(TEST_IPREASM_TARGET)
	$(CC) $(CFLAGS) -DVERBOSE -o $(TESTDIR)/$(TEST_IPREASM_TARGET) $(TEST_IPREASM_SRC)
	./$(TESTDIR)/$(TEST_IPREASM_TARGET)

# ============================================================
#  HTTP 提取测试
# ============================================================

TEST_HTTP_TARGET = test_http_extract

$(TESTDIR)/$(TEST_HTTP_TARGET): $(TEST_HTTP_SRC) include/http_extract.h include/common.h
	$(CC) $(CFLAGS) -o $@ $(TEST_HTTP_SRC)

test-http: $(TESTDIR)/$(TEST_HTTP_TARGET)
	./$(TESTDIR)/$(TEST_HTTP_TARGET)

test-http-verbose: $(TESTDIR)/$(TEST_HTTP_TARGET)
	$(CC) $(CFLAGS) -DVERBOSE -o $(TESTDIR)/$(TEST_HTTP_TARGET) $(TEST_HTTP_SRC)
	./$(TESTDIR)/$(TEST_HTTP_TARGET)

# ============================================================
#  清理与运行
# ============================================================

clean:
	rm -f $(TARGET) $(SRCDIR)/*.o
	rm -f $(TESTDIR)/test_protocol $(TESTDIR)/$(TEST_REASM_TARGET) \
	      $(TESTDIR)/$(TEST_IPREASM_TARGET) $(TESTDIR)/$(TEST_HTTP_TARGET)
	rm -f $(TESTDIR)/*.o

run: $(TARGET)
	sudo ./$(TARGET)
