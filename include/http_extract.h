#ifndef HTTP_EXTRACT_H
#define HTTP_EXTRACT_H

/*
 * http_extract.h — HTTP 请求/响应完整提取
 *
 * 从 TCP 重组后的连续数据流中解析完整的 HTTP 报文。
 * 支持：
 *   - HTTP 请求/响应首行解析
 *   - HTTP header 键值对提取
 *   - Content-Length 指定 body
 *   - Transfer-Encoding: chunked
 *   - Connection: close 终止
 *   - 多报文提取（HTTP pipelining）
 */

#include <stdint.h>
#include <stddef.h>

/* ============================================================
 *  常量
 * ============================================================ */

/* HTTP 方法枚举 */
#define HTTP_METHOD_GET        0
#define HTTP_METHOD_POST       1
#define HTTP_METHOD_PUT        2
#define HTTP_METHOD_DELETE     3
#define HTTP_METHOD_HEAD       4
#define HTTP_METHOD_OPTIONS    5
#define HTTP_METHOD_PATCH      6
#define HTTP_METHOD_CONNECT    7
#define HTTP_METHOD_TRACE      8
#define HTTP_METHOD_UNKNOWN    9

/* HTTP 消息类型 */
#define HTTP_TYPE_REQUEST      0
#define HTTP_TYPE_RESPONSE     1

/* HTTP header 最大数量 */
#define HTTP_MAX_HEADERS       128

/* 单个 header name/value 最大长度 */
#define HTTP_MAX_HEADER_LEN    4096

/* HTTP version 字符串最大长度 */
#define HTTP_MAX_VERSION_LEN   16

/* HTTP URI 最大长度 */
#define HTTP_MAX_URI_LEN       4096

/* 状态文本最大长度 */
#define HTTP_MAX_STATUS_LEN    256

/* ============================================================
 *  数据结构
 * ============================================================ */

struct http_header {
    char   name[HTTP_MAX_HEADER_LEN];    /* Header 名称 */
    char   value[HTTP_MAX_HEADER_LEN];   /* Header 值 */
};

struct http_message {
    int     type;                        /* HTTP_TYPE_REQUEST / HTTP_TYPE_RESPONSE */

    /* ---- 请求行 ---- */
    int     method;                      /* HTTP_METHOD_* */
    char    method_str[16];              /* "GET", "POST", ... */
    char    uri[HTTP_MAX_URI_LEN];       /* 请求 URI */

    /* ---- 响应行 ---- */
    int     status_code;                 /* 200, 404, ... */
    char    status_text[HTTP_MAX_STATUS_LEN]; /* "OK", "Not Found", ... */

    /* ---- 通用 ---- */
    char    version[HTTP_MAX_VERSION_LEN]; /* "HTTP/1.1" */

    /* ---- Headers ---- */
    struct http_header headers[HTTP_MAX_HEADERS];
    int     header_count;

    /* ---- Body ---- */
    uint8_t *body;                       /* 消息体 */
    size_t   body_len;                   /* 消息体长度 */
    size_t   body_cap;                   /* 消息体缓冲区容量 */

    /* ---- 解析状态 ---- */
    size_t   total_msg_len;              /* 整条 HTTP 报文的总字节数（用于跳过） */
    int      complete;                   /* 1=已完整解析 */
};

/* ============================================================
 *  HTTP 解析器状态
 * ============================================================ */

struct http_parser {
    /* 当前正在解析的消息 */
    struct http_message *current_msg;

    /* 内部解析阶段 */
    int     stage;                       /* 0=start_line, 1=headers, 2=body, 3=done */

    /* 累积的已解析数据 */
    uint8_t *buf;                        /* 累积缓冲区 */
    size_t   buf_len;                    /* 已累积的字节数 */
    size_t   buf_cap;                    /* 缓冲区容量 */

    /* 解析状态 */
    int      has_content_length;
    size_t   content_length;
    int      is_chunked;
    int      is_keepalive;               /* Connection: keep-alive */
    int      chunk_size_remaining;

    /* 输出：已解析的完整消息列表 */
    struct http_message *messages;
    int      message_count;
    int      message_cap;

    /* 迭代器：next_message 游标 */
    int      next_idx;
};

/* ============================================================
 *  API 函数
 * ============================================================ */

/*
 * http_parser_init — 初始化 HTTP 解析器
 */
void http_parser_init(struct http_parser *parser);

/*
 * http_parser_destroy — 释放解析器所有资源
 *
 * 释放内部缓冲区及所有已解析的消息资源。
 * 调用后 parser 可重新 init 复用。
 */
void http_parser_destroy(struct http_parser *parser);

/*
 * http_parser_feed — 喂入新的 TCP 重组数据
 *
 * 将 data 追加到内部缓冲区，然后尝试解析完整的 HTTP 报文。
 * 解析出的完整消息可通过 http_parser_next_message() 获取。
 *
 * 参数:
 *   parser — 解析器
 *   data   — 来自 TCP 重组的连续数据
 *   len    — 数据长度
 *
 * 返回: 本次新解析出的完整消息数
 */
int http_parser_feed(struct http_parser *parser,
                      const uint8_t *data, size_t len);

/*
 * http_parser_message_count — 返回已解析的消息总数
 */
int http_parser_message_count(struct http_parser *parser);

/*
 * http_parser_get_message — 按索引获取已解析消息
 *
 * index 范围为 [0, http_parser_message_count() - 1]。
 * 返回的指针在 parser 销毁前有效。
 */
struct http_message *http_parser_get_message(struct http_parser *parser, int index);

/*
 * http_parser_next_message — 遍历下一个已解析消息
 *
 * 基于内部游标依次返回，首次调用返回第一个消息。
 * 返回 NULL 表示已遍历完毕。
 * 调用方不应 free 返回的指针。
 */
struct http_message *http_parser_next_message(struct http_parser *parser);

/*
 * http_parser_has_message — 检查是否有已解析的完整消息
 */
int http_parser_has_message(struct http_parser *parser);

/*
 * http_message_dump — 打印 HTTP 消息摘要
 *
 * 格式示例:
 *   HTTP Request: GET /index.html HTTP/1.1
 *   Host: example.com
 *   Content-Length: 123
 *   Body: 123 bytes
 */
void http_message_dump(const struct http_message *msg);

/*
 * http_get_header — 按名称查找 header 值
 *
 * 返回 header 值指针，未找到返回 NULL。不区分大小写。
 */
const char *http_get_header(const struct http_message *msg, const char *name);

#endif /* HTTP_EXTRACT_H */
