#include "http_extract.h"
#include "common.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

/*
 * http_extract.c — HTTP 请求/响应完整提取实现
 *
 * 从 TCP 重组后的连续数据流中解析 HTTP 报文。
 *
 * == 解析流程 ==
 *   1. 累积数据到内部缓冲区
 *   2. 尝试从缓冲区开始处解析首行（请求行或响应行）
 *   3. 解析 headers，直到空行 (\r\n\r\n 或 \n\n)
 *   4. 根据 Content-Length / Transfer-Encoding: chunked 确定 body 边界
 *   5. 提取 body
 *   6. 输出完整消息，从缓冲区移除已处理数据
 *   7. 重复（支持 HTTP pipelining）
 */

/* ============================================================
 *  内部辅助
 * ============================================================ */

/* 不区分大小写的字符串比较 */
static int strcasecmp_s(const char *a, const char *b)
{
    while (*a && *b) {
        int ca = (unsigned char)*a;
        int cb = (unsigned char)*b;
        if (ca >= 'A' && ca <= 'Z') ca += 0x20;
        if (cb >= 'A' && cb <= 'Z') cb += 0x20;
        if (ca != cb) return ca - cb;
        a++; b++;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

/* 查找子串（定长缓冲区） */
static const uint8_t *memfind(const uint8_t *buf, size_t buf_len,
                               const uint8_t *needle, size_t needle_len)
{
    if (needle_len > buf_len || needle_len == 0)
        return NULL;
    for (size_t i = 0; i <= buf_len - needle_len; i++) {
        if (memcmp(buf + i, needle, needle_len) == 0)
            return buf + i;
    }
    return NULL;
}

/* 解析十六进制字符串长度（用于 chunked encoding） */
static int parse_hex_length(const uint8_t *p, size_t len, size_t *out)
{
    *out = 0;
    size_t i = 0;
    while (i < len) {
        char c = (char)p[i];
        if (c == ';' || c == ' ' || c == '\r' || c == '\n')
            break;
        if (c >= '0' && c <= '9')
            *out = (*out << 4) | (size_t)(c - '0');
        else if (c >= 'a' && c <= 'f')
            *out = (*out << 4) | (size_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')
            *out = (*out << 4) | (size_t)(c - 'A' + 10);
        else
            return -1;
        i++;
    }
    return (int)i;
}

/* ============================================================
 *  首行解析
 * ============================================================ */

static int parse_request_line(const uint8_t *line, size_t line_len,
                               struct http_message *msg)
{
    char buf[1024];
    size_t copy_len = (line_len < sizeof(buf) - 1) ? line_len : sizeof(buf) - 1;
    memcpy(buf, line, copy_len);
    buf[copy_len] = '\0';

    /* 解析 "METHOD URI VERSION" */
    char method[16] = "", uri[HTTP_MAX_URI_LEN] = "", ver[16] = "";
    int n = sscanf(buf, "%15s %4095s %15s", method, uri, ver);
    if (n < 2) return -1;

    /* 匹配 HTTP 方法 */
    msg->type = HTTP_TYPE_REQUEST;
    strncpy(msg->method_str, method, sizeof(msg->method_str) - 1);
    msg->method_str[sizeof(msg->method_str) - 1] = '\0';

    if (strcmp(method, "GET") == 0)         msg->method = HTTP_METHOD_GET;
    else if (strcmp(method, "POST") == 0)   msg->method = HTTP_METHOD_POST;
    else if (strcmp(method, "PUT") == 0)    msg->method = HTTP_METHOD_PUT;
    else if (strcmp(method, "DELETE") == 0)   msg->method = HTTP_METHOD_DELETE;
    else if (strcmp(method, "HEAD") == 0)   msg->method = HTTP_METHOD_HEAD;
    else if (strcmp(method, "OPTIONS") == 0)  msg->method = HTTP_METHOD_OPTIONS;
    else if (strcmp(method, "PATCH") == 0)  msg->method = HTTP_METHOD_PATCH;
    else if (strcmp(method, "CONNECT") == 0)  msg->method = HTTP_METHOD_CONNECT;
    else if (strcmp(method, "TRACE") == 0)  msg->method = HTTP_METHOD_TRACE;
    else                                    msg->method = HTTP_METHOD_UNKNOWN;

    strncpy(msg->uri, uri, sizeof(msg->uri) - 1);
    msg->uri[sizeof(msg->uri) - 1] = '\0';

    if (n >= 3) {
        strncpy(msg->version, ver, sizeof(msg->version) - 1);
        msg->version[sizeof(msg->version) - 1] = '\0';
    } else {
        strncpy(msg->version, "HTTP/0.9", sizeof(msg->version) - 1);
    }

    return 0;
}

static int parse_response_line(const uint8_t *line, size_t line_len,
                                struct http_message *msg)
{
    char buf[1024];
    size_t copy_len = (line_len < sizeof(buf) - 1) ? line_len : sizeof(buf) - 1;
    memcpy(buf, line, copy_len);
    buf[copy_len] = '\0';

    char ver[16] = "";
    int code = 0;
    int n = sscanf(buf, "%15s %d", ver, &code);
    if (n < 2) return -1;

    msg->type = HTTP_TYPE_RESPONSE;
    msg->status_code = code;
    strncpy(msg->version, ver, sizeof(msg->version) - 1);
    msg->version[sizeof(msg->version) - 1] = '\0';

    /* 提取状态文本（status code 后的剩余部分） */
    char *code_pos = strchr(buf, ' ');
    if (code_pos) {
        code_pos = strchr(code_pos + 1, ' ');
        if (code_pos) {
            code_pos++; /* 跳过空格 */
            /* 去掉尾部 \r */
            size_t st_len = strlen(code_pos);
            while (st_len > 0 && (code_pos[st_len - 1] == '\r' ||
                                  code_pos[st_len - 1] == '\n'))
                code_pos[--st_len] = '\0';
            strncpy(msg->status_text, code_pos, sizeof(msg->status_text) - 1);
            msg->status_text[sizeof(msg->status_text) - 1] = '\0';
        }
    }

    return 0;
}

/* ============================================================
 *  Header 解析
 * ============================================================ */

static int parse_header_line(const uint8_t *line, size_t line_len,
                              struct http_message *msg)
{
    if (msg->header_count >= HTTP_MAX_HEADERS)
        return -1;

    char buf[8192];
    size_t copy_len = (line_len < sizeof(buf) - 1) ? line_len : sizeof(buf) - 1;
    memcpy(buf, line, copy_len);
    buf[copy_len] = '\0';

    char *colon = strchr(buf, ':');
    if (colon == NULL)
        return -1;

    *colon = '\0';
    char *name = buf;
    char *value = colon + 1;

    /* 跳过 name 尾部空格 */
    char *p = name + strlen(name) - 1;
    while (p >= name && (*p == ' ' || *p == '\t')) *p-- = '\0';

    /* 跳过 value 前导空格 */
    while (*value == ' ' || *value == '\t') value++;

    /* 去掉 value 尾部 \r */
    p = value + strlen(value) - 1;
    while (p >= value && (*p == '\r' || *p == '\n')) *p-- = '\0';

    {
        size_t n = strlen(name);
        if (n >= HTTP_MAX_HEADER_LEN) n = HTTP_MAX_HEADER_LEN - 1;
        memcpy(msg->headers[msg->header_count].name, name, n);
        msg->headers[msg->header_count].name[n] = '\0';
    }
    {
        size_t n = strlen(value);
        if (n >= HTTP_MAX_HEADER_LEN) n = HTTP_MAX_HEADER_LEN - 1;
        memcpy(msg->headers[msg->header_count].value, value, n);
        msg->headers[msg->header_count].value[n] = '\0';
    }
    msg->header_count++;

    return 0;
}

/* ============================================================
 *  Body 长度判断
 * ============================================================ */

static void determine_body_length(struct http_parser *parser,
                                   struct http_message *msg)
{
    parser->has_content_length = 0;
    parser->content_length = 0;
    parser->is_chunked = 0;
    parser->is_keepalive = 1;

    /* 检查 Transfer-Encoding */
    for (int i = 0; i < msg->header_count; i++) {
        if (strcasecmp_s(msg->headers[i].name, "Transfer-Encoding") == 0) {
            if (strcasecmp_s(msg->headers[i].value, "chunked") == 0) {
                parser->is_chunked = 1;
            }
        }
    }

    /* 检查 Content-Length */
    for (int i = 0; i < msg->header_count; i++) {
        if (strcasecmp_s(msg->headers[i].name, "Content-Length") == 0) {
            parser->has_content_length = 1;
            /* 使用 strtoll 校验负数/非法值 */
            char *end = NULL;
            long long cl_val = strtoll(msg->headers[i].value, &end, 10);
            if (end == msg->headers[i].value || cl_val < 0 || cl_val > 1024LL * 1024 * 1024) {
                parser->content_length = 0;
            } else {
                parser->content_length = (size_t)cl_val;
            }
        }
    }

    /* 检查 Connection */
    for (int i = 0; i < msg->header_count; i++) {
        if (strcasecmp_s(msg->headers[i].name, "Connection") == 0) {
            if (strcasecmp_s(msg->headers[i].value, "close") == 0)
                parser->is_keepalive = 0;
        }
    }

    /* 响应码 1xx, 204, 304 无 body */
    if (msg->type == HTTP_TYPE_RESPONSE) {
        if (msg->status_code == 204 || msg->status_code == 304 ||
            (msg->status_code >= 100 && msg->status_code < 200)) {
            parser->content_length = 0;
            parser->has_content_length = 1;
            parser->is_chunked = 0;
        }
    }

    /* HEAD 请求的响应无 body（但可能有 Content-Length header） */
    /* 注意：这里依赖调用方知道是 HEAD 请求 */
}

/* ============================================================
 *  消息体构建
 * ============================================================ */

static int ensure_body_buf(struct http_message *msg, size_t needed)
{
    if (msg->body_cap >= needed)
        return 0;

    size_t new_cap = msg->body_cap == 0 ? 4096 : msg->body_cap;
    while (new_cap < needed)
        new_cap *= 2;

    uint8_t *new_buf = realloc(msg->body, new_cap);
    if (new_buf == NULL)
        return -1;

    msg->body = new_buf;
    msg->body_cap = new_cap;
    return 0;
}

/* ============================================================
 *  累积缓冲区管理
 * ============================================================ */

static int ensure_parser_buf(struct http_parser *parser, size_t needed)
{
    if (parser->buf_cap >= needed)
        return 0;

    size_t new_cap = parser->buf_cap == 0 ? 8192 : parser->buf_cap;
    while (new_cap < needed)
        new_cap *= 2;

    uint8_t *new_buf = realloc(parser->buf, new_cap);
    if (new_buf == NULL)
        return -1;

    parser->buf = new_buf;
    parser->buf_cap = new_cap;
    return 0;
}

/* ============================================================
 *  核心解析：尝试从缓冲区解析一个完整消息
 * ============================================================ */

/*
 * try_parse_one — 尝试从 parser 缓冲区的开头解析一个完整 HTTP 消息
 *
 * 成功时：
 *   - 分配并填充 msg
 *   - 从缓冲区头部移除已使用的字节
 *   - 返回 1
 *
 * 需要更多数据时返回 0
 * 解析错误时返回 -1
 */
static int try_parse_one(struct http_parser *parser)
{
    const uint8_t *buf = parser->buf;
    size_t len = parser->buf_len;

    if (len == 0)
        return 0;

    /* ---- 找首行结束 ---- */
    const uint8_t *crlf = memfind(buf, len, (const uint8_t *)"\r\n", 2);
    const uint8_t *lf   = memfind(buf, len, (const uint8_t *)"\n", 1);

    const uint8_t *line_end;
    size_t line_skip;
    if (crlf && (!lf || crlf <= lf)) {
        line_end = crlf;
        line_skip = 2;
    } else if (lf) {
        line_end = lf;
        line_skip = 1;
    } else {
        return 0;  /* 首行未完整 */
    }

    size_t line_len = (size_t)(line_end - buf);
    if (line_len == 0)
        return 0;  /* 空行不可能作为首行 */

    /* ---- 分配消息结构体 ---- */
    struct http_message *msg = calloc(1, sizeof(struct http_message));
    if (msg == NULL)
        return -1;

    /* ---- 判断是请求还是响应 ---- */
    int is_response = (line_len >= 5 && memcmp(buf, "HTTP/", 5) == 0);
    int parse_ok;

    if (is_response) {
        parse_ok = parse_response_line(buf, line_len, msg);
    } else {
        parse_ok = parse_request_line(buf, line_len, msg);
    }

    if (parse_ok != 0) {
        free(msg);
        return -1;  /* 不是 HTTP */
    }

    /* ---- 跳过首行 ---- */
    size_t consumed = line_len + line_skip;
    buf += consumed;
    len -= consumed;

    /* ---- 解析 headers ---- */
    int has_empty_line = 0;
    size_t header_consumed = 0;

    while (len > 0) {
        /* 检查空行（header 结束） */
        if (len >= 2 && buf[0] == '\r' && buf[1] == '\n') {
            has_empty_line = 1;
            header_consumed += 2;
            buf += 2;
            len -= 2;
            break;
        }
        if (len >= 1 && buf[0] == '\n') {
            has_empty_line = 1;
            header_consumed += 1;
            buf += 1;
            len -= 1;
            break;
        }

        /* 找 header 行尾 */
        crlf = memfind(buf, len, (const uint8_t *)"\r\n", 2);
        lf   = memfind(buf, len, (const uint8_t *)"\n", 1);

        const uint8_t *hdr_end;
        size_t hdr_skip;
        if (crlf && (!lf || crlf <= lf)) {
            hdr_end = crlf;
            hdr_skip = 2;
        } else if (lf) {
            hdr_end = lf;
            hdr_skip = 1;
        } else {
            break;  /* header 行未完整 */
        }

        size_t hdr_len = (size_t)(hdr_end - buf);
        if (hdr_len == 0) {
            /* 空行但在没有 \r 的情况下… 重新检查 */
            has_empty_line = 1;
            header_consumed += hdr_skip;
            buf += hdr_skip;
            len -= hdr_skip;
            break;
        }

        if (parse_header_line(buf, hdr_len, msg) != 0)
            break;  /* header 解析失败，跳过 */

        header_consumed += hdr_len + hdr_skip;
        buf += hdr_len + hdr_skip;
        len -= hdr_len + hdr_skip;
    }

    if (!has_empty_line) {
        /* 未找到空行 → 还需要更多数据 */
        free(msg);
        return 0;
    }

    consumed += header_consumed;

    /* ---- 确定 body 长度 ---- */
    determine_body_length(parser, msg);

    /* ---- 提取 body ---- */
    if (parser->is_chunked) {
        /* 分块编码 */
        size_t body_pos = 0;

        while (len > 0) {
            /* 找 chunk-size 行 */
            crlf = memfind(buf, len, (const uint8_t *)"\r\n", 2);
            if (crlf == NULL)
                break;  /* 需要更多数据 */

            size_t chunk_size_line = (size_t)(crlf - buf);

            size_t chunk_size = 0;
            if (parse_hex_length(buf, chunk_size_line, &chunk_size) < 0)
                break;  /* 格式错误 */

            size_t chunk_header_skip = chunk_size_line + 2;
            if (chunk_size == 0) {
                /* 最后一个 chunk */
                consumed += chunk_header_skip;
                if (len >= chunk_header_skip + 2) {
                    /* 跳过尾部 CRLF */
                    if (buf[chunk_header_skip] == '\r' &&
                        buf[chunk_header_skip + 1] == '\n') {
                        consumed += 2;
                    }
                }
                msg->complete = 1;
                break;
            }

            /* 检查数据完整性 */
            if (len < chunk_header_skip + chunk_size + 2)
                break;  /* 需要更多数据 */

            /* 复制 chunk 数据 */
            if (ensure_body_buf(msg, body_pos + chunk_size) != 0)
                break;

            memcpy(msg->body + body_pos,
                   buf + chunk_header_skip, chunk_size);
            body_pos += chunk_size;

            size_t chunk_total = chunk_header_skip + chunk_size + 2;  /* +2 for CRLF */
            consumed += chunk_total;
            buf += chunk_total;
            len -= chunk_total;
        }

        msg->body_len = body_pos;

        /* 如果已完成，减掉 trailing CRLF (已经做了) */
        if (msg->complete) {
            /* 已成功解析完整 chunked body */
        } else {
            /* 未完成：从 consumed 中回退，保留数据 */
            /* 但 msg 已创建，稍后由调用方处理 */
            /* 对于未完成的 chunked，标记为未完成 */
        }
    } else if (parser->has_content_length) {
        /* Content-Length 指定 body */
        if (parser->content_length > 0) {
            if (len >= parser->content_length) {
                if (ensure_body_buf(msg, parser->content_length) == 0) {
                    memcpy(msg->body, buf, parser->content_length);
                    msg->body_len = parser->content_length;
                    consumed += parser->content_length;
                }
            } else {
                /* body 未完整 */
                free(msg);
                return 0;
            }
        }
        msg->complete = 1;
    } else if (msg->type == HTTP_TYPE_RESPONSE &&
               msg->status_code >= 200 && msg->status_code != 204 &&
               msg->status_code != 304) {
        /* 无 Content-Length 也无 Transfer-Encoding 的响应 */
        if (parser->is_keepalive) {
            /* keep-alive + no body indicators → body 长度为 0 */
            msg->complete = 1;
        } else {
            /* Connection: close — 需要等连接关闭才能确定 body 结束 */
            /* 此处标记为需要更多数据 */
            free(msg);
            return 0;
        }
    } else {
        /* 无 body（如 GET 请求、204 响应等） */
        msg->complete = 1;
    }

    msg->total_msg_len = consumed;

    /* ---- 添加到 parser 的消息列表 ---- */
    if (parser->message_count >= parser->message_cap) {
        int new_cap = parser->message_cap == 0 ? 16 : parser->message_cap * 2;
        struct http_message *new_msgs = realloc(parser->messages,
                                                  new_cap * sizeof(struct http_message));
        if (new_msgs == NULL) {
            /* 释放当前消息 */
            if (msg->body) free(msg->body);
            free(msg);
            return -1;
        }
        parser->messages = new_msgs;
        parser->message_cap = new_cap;
    }

    parser->messages[parser->message_count] = *msg;
    parser->message_count++;
    free(msg);  /* 释放临时结构，数据已复制 */

    /* ---- 从缓冲区头部移除 ---- */
    if (consumed > 0) {
        if (consumed < parser->buf_len) {
            memmove(parser->buf, parser->buf + consumed,
                    parser->buf_len - consumed);
        }
        parser->buf_len -= consumed;
    }

    return 1;
}

/* ============================================================
 *  公共 API
 * ============================================================ */

void http_parser_init(struct http_parser *parser)
{
    memset(parser, 0, sizeof(struct http_parser));
    parser->stage = 0;
    parser->is_keepalive = 1;
}

void http_parser_destroy(struct http_parser *parser)
{
    if (parser == NULL) return;

    if (parser->buf) {
        free(parser->buf);
        parser->buf = NULL;
    }
    parser->buf_len = 0;
    parser->buf_cap = 0;

    /* 释放每个消息的 body */
    for (int i = 0; i < parser->message_count; i++) {
        if (parser->messages[i].body)
            free(parser->messages[i].body);
    }
    if (parser->messages)
        free(parser->messages);

    parser->messages = NULL;
    parser->message_count = 0;
    parser->message_cap = 0;

    if (parser->current_msg) {
        if (parser->current_msg->body)
            free(parser->current_msg->body);
        free(parser->current_msg);
        parser->current_msg = NULL;
    }
}

int http_parser_feed(struct http_parser *parser,
                      const uint8_t *data, size_t len)
{
    if (parser == NULL || (data == NULL && len > 0))
        return -1;
    if (len == 0)
        return 0;

    /* 追加到内部缓冲区 */
    if (ensure_parser_buf(parser, parser->buf_len + len) != 0) {
        LOG_ERROR("http_extract: buffer resize failed");
        return -1;
    }

    memcpy(parser->buf + parser->buf_len, data, len);
    parser->buf_len += len;

    /* 尝试解析所有完整消息 */
    int parsed_count = 0;
    int ret;

    while ((ret = try_parse_one(parser)) == 1) {
        parsed_count++;
    }

    if (ret == -1) {
        /* 解析错误：可能是非 HTTP 数据，跳过一行 */
        const uint8_t *buf = parser->buf;
        size_t remaining = parser->buf_len;
        const uint8_t *crlf = memfind(buf, remaining, (const uint8_t *)"\r\n", 2);
        const uint8_t *lf   = memfind(buf, remaining, (const uint8_t *)"\n", 1);

        size_t skip;
        if (crlf && (!lf || crlf <= lf))
            skip = (size_t)(crlf - buf) + 2;
        else if (lf)
            skip = (size_t)(lf - buf) + 1;
        else
            skip = remaining;

        if (skip > 0 && skip <= parser->buf_len) {
            memmove(parser->buf, parser->buf + skip, parser->buf_len - skip);
            parser->buf_len -= skip;
            LOG_WARN("http_extract: parse error, skipped %zu bytes", skip);
        }
    }

    return parsed_count;
}

int http_parser_message_count(struct http_parser *parser)
{
    return (parser != NULL) ? parser->message_count : 0;
}

struct http_message *http_parser_get_message(struct http_parser *parser, int index)
{
    if (parser == NULL || index < 0 || index >= parser->message_count)
        return NULL;
    return &parser->messages[index];
}

struct http_message *http_parser_next_message(struct http_parser *parser)
{
    if (parser == NULL || parser->next_idx >= parser->message_count)
        return NULL;

    struct http_message *msg = &parser->messages[parser->next_idx];
    parser->next_idx++;
    return msg;
}

int http_parser_has_message(struct http_parser *parser)
{
    return (parser != NULL && parser->message_count > 0);
}

const char *http_get_header(const struct http_message *msg, const char *name)
{
    if (msg == NULL || name == NULL)
        return NULL;

    for (int i = 0; i < msg->header_count; i++) {
        if (strcasecmp_s(msg->headers[i].name, name) == 0)
            return msg->headers[i].value;
    }
    return NULL;
}

void http_message_dump(const struct http_message *msg)
{
    if (msg == NULL) return;

    if (msg->type == HTTP_TYPE_REQUEST) {
        printf("HTTP Request: %s %s %s\n",
               msg->method_str, msg->uri, msg->version);
    } else {
        const char *code_desc = NULL;
        switch (msg->status_code) {
        case 100: code_desc = "Continue"; break;
        case 200: code_desc = "OK"; break;
        case 201: code_desc = "Created"; break;
        case 204: code_desc = "No Content"; break;
        case 206: code_desc = "Partial Content"; break;
        case 301: code_desc = "Moved Permanently"; break;
        case 302: code_desc = "Found"; break;
        case 304: code_desc = "Not Modified"; break;
        case 400: code_desc = "Bad Request"; break;
        case 401: code_desc = "Unauthorized"; break;
        case 403: code_desc = "Forbidden"; break;
        case 404: code_desc = "Not Found"; break;
        case 405: code_desc = "Method Not Allowed"; break;
        case 408: code_desc = "Request Timeout"; break;
        case 413: code_desc = "Payload Too Large"; break;
        case 429: code_desc = "Too Many Requests"; break;
        case 500: code_desc = "Internal Server Error"; break;
        case 502: code_desc = "Bad Gateway"; break;
        case 503: code_desc = "Service Unavailable"; break;
        case 504: code_desc = "Gateway Timeout"; break;
        }
        printf("HTTP Response: %s %d %s | %s\n",
               msg->version, msg->status_code,
               msg->status_text[0] ? msg->status_text : (code_desc ? code_desc : ""),
               msg->complete ? "complete" : "partial");
    }

    for (int i = 0; i < msg->header_count && i < 16; i++) {
        printf("  %s: %s\n", msg->headers[i].name, msg->headers[i].value);
    }
    if (msg->header_count > 16) {
        printf("  ... (%d more headers)\n", msg->header_count - 16);
    }

    if (msg->body_len > 0) {
        printf("  Body: %zu bytes", msg->body_len);
        if (msg->body_len <= 128) {
            printf(" = \"");
            for (size_t i = 0; i < msg->body_len; i++) {
                char c = (char)msg->body[i];
                if (c >= 0x20 && c <= 0x7E)
                    putchar(c);
                else
                    printf("\\x%02x", msg->body[i]);
            }
            printf("\"");
        }
        printf("\n");
    }

    if (!msg->complete) {
        printf("  [INCOMPLETE]\n");
    }
}
