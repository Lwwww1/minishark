/*
 * test_http_extract.c — HTTP 请求/响应提取测试
 *
 * 编译：gcc -Wall -Wextra -O2 -g -I../include test_http_extract.c ../src/http_extract.c -o test_http_extract
 * 运行：./test_http_extract
 */

#include "http_extract.h"
#include "common.h"
#include "protocol.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ============================================================
 *  测试基础设施
 * ============================================================ */

static int tests_passed = 0;
static int tests_failed = 0;
static int current_test = 0;

static void test_begin(const char *name)
{
    current_test++;
#ifdef VERBOSE
    printf("\n--- [Test %d] %s ---\n", current_test, name);
#else
    (void)name;
#endif
}

static void test_end(int result, const char *name)
{
    if (result == 0) {
        tests_passed++;
#ifdef VERBOSE
        printf("  PASS: %s\n", name);
#else
        (void)name;
#endif
    } else {
        tests_failed++;
        printf("  FAIL: %s (expected 0, got %d)\n", name, result);
    }
}

static void test_end_int_eq(int got, int expected, const char *name)
{
    if (got == expected) {
        tests_passed++;
#ifdef VERBOSE
        printf("  PASS: %s (=%d)\n", name, got);
#endif
    } else {
        tests_failed++;
        printf("  FAIL: %s (expected %d, got %d)\n", name, expected, got);
    }
}

static void test_end_nonnull(void *ptr, const char *name)
{
    if (ptr != NULL) {
        tests_passed++;
#ifdef VERBOSE
        printf("  PASS: %s\n", name);
#endif
    } else {
        tests_failed++;
        printf("  FAIL: %s (NULL)\n", name);
    }
}

static __attribute__((unused))
void test_end_null(void *ptr, const char *name)
{
    if (ptr == NULL) {
        tests_passed++;
#ifdef VERBOSE
        printf("  PASS: %s\n", name);
#endif
    } else {
        tests_failed++;
        printf("  FAIL: %s (not NULL)\n", name);
    }
}

static void test_end_str_eq(const char *got, const char *expected, const char *name)
{
    if ((got == NULL && expected == NULL) ||
        (got != NULL && expected != NULL && strcmp(got, expected) == 0)) {
        tests_passed++;
#ifdef VERBOSE
        printf("  PASS: %s (=\"%s\")\n", name, got ? got : "(null)");
#endif
    } else {
        tests_failed++;
        printf("  FAIL: %s (expected \"%s\", got \"%s\")\n",
               name, expected ? expected : "(null)", got ? got : "(null)");
    }
}

/* ============================================================
 *  测试用例
 * ============================================================ */

static void test_parse_simple_get(void)
{
    test_begin("HTTP: parse simple GET request");
    const char *req = "GET /index.html HTTP/1.1\r\n"
                      "Host: example.com\r\n"
                      "User-Agent: TestAgent\r\n"
                      "\r\n";

    struct http_parser parser;
    http_parser_init(&parser);

    int n = http_parser_feed(&parser, (const uint8_t *)req, strlen(req));
    test_end_int_eq(n, 1, "1 message parsed");

    /* Check message */
    struct http_message *msg = http_parser_get_message(&parser, 0);
    test_end_nonnull(msg, "got message");
    if (msg) {
        test_end_int_eq(msg->type, HTTP_TYPE_REQUEST, "type = request");
        test_end_int_eq(msg->method, HTTP_METHOD_GET, "method = GET");
        test_end_str_eq(msg->uri, "/index.html", "uri = /index.html");
        test_end_str_eq(msg->version, "HTTP/1.1", "version = HTTP/1.1");
        test_end_int_eq(msg->header_count, 2, "2 headers");
        test_end_int_eq(msg->complete, 1, "message complete");

        /* Check specific header */
        const char *host = http_get_header(msg, "Host");
        test_end_str_eq(host, "example.com", "Host header = example.com");
    }

    http_parser_destroy(&parser);
}

static void test_parse_response_with_body(void)
{
    test_begin("HTTP: parse response with Content-Length body");
    const char *resp = "HTTP/1.1 200 OK\r\n"
                       "Content-Type: text/html\r\n"
                       "Content-Length: 13\r\n"
                       "\r\n"
                       "Hello, World!";

    struct http_parser parser;
    http_parser_init(&parser);

    int n = http_parser_feed(&parser, (const uint8_t *)resp, strlen(resp));
    test_end_int_eq(n, 1, "1 message parsed");

    struct http_message *msg = http_parser_get_message(&parser, 0);
    test_end_nonnull(msg, "got message");
    if (msg) {
        test_end_int_eq(msg->type, HTTP_TYPE_RESPONSE, "type = response");
        test_end_int_eq(msg->status_code, 200, "status = 200");
        test_end_str_eq(msg->version, "HTTP/1.1", "version = HTTP/1.1");
        test_end_int_eq(msg->complete, 1, "message complete");
        test_end_int_eq((int)msg->body_len, 13, "body length = 13");
        if (msg->body && msg->body_len >= 13) {
            test_end(memcmp(msg->body, "Hello, World!", 13), "body content matches");
        }
    }

    http_parser_destroy(&parser);
}

static void test_parse_response_no_body(void)
{
    test_begin("HTTP: 204 No Content has no body");
    const char *resp = "HTTP/1.1 204 No Content\r\n"
                       "Server: nginx\r\n"
                       "\r\n";

    struct http_parser parser;
    http_parser_init(&parser);

    int n = http_parser_feed(&parser, (const uint8_t *)resp, strlen(resp));
    test_end_int_eq(n, 1, "1 message parsed");

    struct http_message *msg = http_parser_get_message(&parser, 0);
    if (msg) {
        test_end_int_eq(msg->status_code, 204, "status = 204");
        test_end_int_eq((int)msg->body_len, 0, "body length = 0");
        test_end_int_eq(msg->complete, 1, "message complete");
    }

    http_parser_destroy(&parser);
}

static void test_parse_chunked_response(void)
{
    test_begin("HTTP: parse chunked transfer encoding");
    const char *resp = "HTTP/1.1 200 OK\r\n"
                       "Transfer-Encoding: chunked\r\n"
                       "\r\n"
                       "5\r\n"
                       "Hello\r\n"
                       "6\r\n"
                       " World\r\n"
                       "0\r\n"
                       "\r\n";

    struct http_parser parser;
    http_parser_init(&parser);

    int n = http_parser_feed(&parser, (const uint8_t *)resp, strlen(resp));
    test_end_int_eq(n, 1, "1 chunked message parsed");

    struct http_message *msg = http_parser_get_message(&parser, 0);
    if (msg) {
        test_end_int_eq(msg->type, HTTP_TYPE_RESPONSE, "type = response");
        test_end_int_eq(msg->status_code, 200, "status = 200");
        test_end_int_eq(msg->complete, 1, "message complete");
        test_end_int_eq((int)msg->body_len, 11, "chunked body length = 11");
        if (msg->body && msg->body_len >= 11) {
            test_end(memcmp(msg->body, "Hello World", 11), "chunked body content matches");
        }
    }

    http_parser_destroy(&parser);
}

static void test_parse_post_request(void)
{
    test_begin("HTTP: parse POST request with body");
    const char *req = "POST /api/data HTTP/1.1\r\n"
                      "Host: api.example.com\r\n"
                      "Content-Type: application/json\r\n"
                      "Content-Length: 27\r\n"
                      "\r\n"
                      "{\"key\": \"value\", \"num\": 42}";

    struct http_parser parser;
    http_parser_init(&parser);

    int n = http_parser_feed(&parser, (const uint8_t *)req, strlen(req));
    test_end_int_eq(n, 1, "1 POST parsed");

    struct http_message *msg = http_parser_get_message(&parser, 0);
    if (msg) {
        test_end_int_eq(msg->type, HTTP_TYPE_REQUEST, "type = request");
        test_end_int_eq(msg->method, HTTP_METHOD_POST, "method = POST");
        test_end_str_eq(msg->uri, "/api/data", "uri = /api/data");
        test_end_int_eq(msg->header_count, 3, "3 headers");
        test_end_int_eq((int)msg->body_len, 27, "body length = 27");
        if (msg->body && msg->body_len >= 27) {
            test_end(memcmp(msg->body, "{\"key\": \"value\", \"num\": 42}", 27),
                     "JSON body matches");
        }
    }

    http_parser_destroy(&parser);
}

static void test_pipelining(void)
{
    test_begin("HTTP: pipelining (two requests in one buffer)");
    const char *pipe = "GET /a HTTP/1.1\r\n"
                       "Host: a.com\r\n"
                       "\r\n"
                       "GET /b HTTP/1.1\r\n"
                       "Host: b.com\r\n"
                       "\r\n";

    struct http_parser parser;
    http_parser_init(&parser);

    int n = http_parser_feed(&parser, (const uint8_t *)pipe, strlen(pipe));
    test_end_int_eq(n, 2, "2 pipelined requests parsed");
    test_end_int_eq(http_parser_message_count(&parser), 2, "message count = 2");

    struct http_message *m1 = http_parser_get_message(&parser, 0);
    struct http_message *m2 = http_parser_get_message(&parser, 1);
    test_end_nonnull(m1, "first message");
    test_end_nonnull(m2, "second message");

    if (m1) {
        test_end_str_eq(m1->uri, "/a", "first request URI = /a");
    }
    if (m2) {
        test_end_str_eq(m2->uri, "/b", "second request URI = /b");
    }

    http_parser_destroy(&parser);
}

static void test_parse_garbage_skip(void)
{
    test_begin("HTTP: garbage data skipped gracefully");
    const char *garbage = "NOT HTTP DATA\r\n"
                          "GET /real HTTP/1.1\r\n"
                          "Host: real.com\r\n"
                          "\r\n";

    struct http_parser parser;
    http_parser_init(&parser);

    int n = http_parser_feed(&parser, (const uint8_t *)garbage, strlen(garbage));
    /* The first line is garbage, the parser should skip it and find the valid request */
    test_end_int_eq(n, 1, "1 valid message found after garbage skip");

    struct http_message *msg = http_parser_get_message(&parser, 0);
    if (msg) {
        test_end_str_eq(msg->uri, "/real", "uri = /real after garbage skip");
    }

    http_parser_destroy(&parser);
}

static void test_parser_reset(void)
{
    test_begin("HTTP: parser re-initialization works");
    struct http_parser parser;
    http_parser_init(&parser);

    const char *req1 = "GET /first HTTP/1.1\r\n\r\n";
    http_parser_feed(&parser, (const uint8_t *)req1, strlen(req1));
    test_end_int_eq(http_parser_message_count(&parser), 1, "1 message after first feed");

    http_parser_destroy(&parser);

    /* Re-init */
    http_parser_init(&parser);
    test_end_int_eq(http_parser_message_count(&parser), 0, "0 messages after re-init");

    const char *req2 = "GET /second HTTP/1.1\r\n\r\n";
    http_parser_feed(&parser, (const uint8_t *)req2, strlen(req2));
    test_end_int_eq(http_parser_message_count(&parser), 1, "1 message after second feed");

    struct http_message *msg = http_parser_get_message(&parser, 0);
    if (msg) {
        test_end_str_eq(msg->uri, "/second", "uri = /second after re-init");
    }

    http_parser_destroy(&parser);
}

/* ============================================================
 *  主测试入口
 * ============================================================ */

int main(void)
{
    printf("============================================\n");
    printf("  minishark — HTTP Extraction Test Suite\n");
    printf("============================================\n\n");

    printf("--- Request Parsing ---\n");
    test_parse_simple_get();
    test_parse_post_request();
    printf("\n");

    printf("--- Response Parsing ---\n");
    test_parse_response_with_body();
    test_parse_response_no_body();
    test_parse_chunked_response();
    printf("\n");

    printf("--- Advanced ---\n");
    test_pipelining();
    test_parse_garbage_skip();
    test_parser_reset();
    printf("\n");

    printf("============================================\n");
    printf("  Results: %d passed, %d failed out of %d\n",
           tests_passed, tests_failed, current_test);
    printf("============================================\n");

    return tests_failed > 0 ? 1 : 0;
}
