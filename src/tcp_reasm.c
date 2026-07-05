#include "tcp_reasm.h"
#include "common.h"
#include "protocol.h"

/*
 * tcp_reasm.c — TCP 流重组的完整实现
 *
 * 基于 5 元组哈希表的流跟踪、按 SEQ 排序插入、
 * TCP 状态机、重叠段处理（去重/重传/部分覆盖）、
 * 以及连续数据重组缓冲区。
 *
 * == 重叠段处理策略 ==
 *   - 完全重复 (same SEQ, same/less length)：丢弃，计数器 +1
 *   - 重传 (same SEQ, longer)：保留已有，追加尾部未覆盖数据
 *   - 部分重叠 (overlap at edges)：截断新段的覆盖部分，保留新数据
 *   - 完全覆盖（新段覆盖已有段）：移除已有段，保留新段
 *
 * == 连续重组 ==
 *   tcp_reasm_assemble() 在每次插入后被调用，
 *   从 segments 链表中取出 SEQ 连续的段，追加到 reasm_buf。
 *
 * 哈希表使用分离链接法 (separate chaining)，每个桶是一个单向链表。
 */

/* ============================================================
 *  内部辅助
 * ============================================================ */

/* TCP 状态名称（用于调试打印） */
static const char *tcp_state_name(tcp_state_t s)
{
    switch (s) {
    case TCP_STATE_CLOSED:      return "CLOSED";
    case TCP_STATE_SYN_RCVD:    return "SYN_RCVD";
    case TCP_STATE_ESTABLISHED: return "ESTABLISHED";
    case TCP_STATE_FIN_RCVD:    return "FIN_RCVD";
    case TCP_STATE_CLOSING:     return "CLOSING";
    default:                    return "UNKNOWN";
    }
}

/* ============================================================
 *  内部哈希表
 * ============================================================ */

/* 哈希表：每个桶指向一个流链表的头 */
static struct tcp_stream *g_buckets[REASM_HASH_SIZE];

/* 统计 */
static int g_stream_count  = 0;   /* 当前活跃流数 */
static int g_seg_total     = 0;   /* 全局段总数 */
static int g_initialized   = 0;   /* 是否已初始化 */

/* ============================================================
 *  哈希与键比较（内部辅助）
 * ============================================================ */

/*
 * hash_key — DJB2 哈希
 *
 * 对 tcp_key 中的所有标识字段进行哈希，返回桶索引。
 */
static size_t hash_key(const struct tcp_key *key)
{
    uint32_t h = 5381;
    const uint8_t *p;
    int i;

    /* 哈希地址族 */
    h = ((h << 5) + h) + key->af;

    /* 哈希源地址 */
    if (key->af == TCP_KEY_AF_IPV4) {
        p = (const uint8_t *)&key->src.ipv4;
        for (i = 0; i < 4; i++)
            h = ((h << 5) + h) + p[i];
    } else {
        for (i = 0; i < 16; i++)
            h = ((h << 5) + h) + key->src.ipv6[i];
    }

    /* 哈希目的地址 */
    if (key->af == TCP_KEY_AF_IPV4) {
        p = (const uint8_t *)&key->dst.ipv4;
        for (i = 0; i < 4; i++)
            h = ((h << 5) + h) + p[i];
    } else {
        for (i = 0; i < 16; i++)
            h = ((h << 5) + h) + key->dst.ipv6[i];
    }

    /* 哈希端口（一个 uint16_t 需 2 字节） */
    p = (const uint8_t *)&key->src_port;
    h = ((h << 5) + h) + p[0];
    h = ((h << 5) + h) + p[1];

    p = (const uint8_t *)&key->dst_port;
    h = ((h << 5) + h) + p[0];
    h = ((h << 5) + h) + p[1];

    /* 哈希协议号 */
    h = ((h << 5) + h) + key->proto;

    return (size_t)(h % REASM_HASH_SIZE);
}

/*
 * key_equal — 比较两个五元组是否完全相同
 */
static int key_equal(const struct tcp_key *a, const struct tcp_key *b)
{
    if (a->af           != b->af)           return 0;
    if (a->src_port     != b->src_port)     return 0;
    if (a->dst_port     != b->dst_port)     return 0;
    if (a->proto        != b->proto)        return 0;

    if (a->af == TCP_KEY_AF_IPV4) {
        return (a->src.ipv4 == b->src.ipv4 &&
                a->dst.ipv4 == b->dst.ipv4);
    } else {
        return (memcmp(a->src.ipv6, b->src.ipv6, 16) == 0 &&
                memcmp(a->dst.ipv6, b->dst.ipv6, 16) == 0);
    }
}

/*
 * key_swap — 交换五元组的源/目的，用于双向查找
 */
static void key_swap(struct tcp_key *out, const struct tcp_key *in)
{
    out->af       = in->af;
    memcpy(&out->src, &in->dst, sizeof(out->src));  /* 交换地址 */
    memcpy(&out->dst, &in->src, sizeof(out->dst));
    out->src_port = in->dst_port;  /* 交换端口 */
    out->dst_port = in->src_port;
    out->proto    = in->proto;
}

/* ============================================================
 *  流与段的内存管理
 * ============================================================ */

/*
 * segment_alloc — 分配并初始化一个 TCP 段
 */
static struct tcp_segment *segment_alloc(uint32_t seq, uint32_t seq_len,
                                          const uint8_t *data, uint16_t data_len,
                                          uint8_t flags)
{
    struct tcp_segment *seg = calloc(1, sizeof(struct tcp_segment));
    if (seg == NULL) {
        LOG_ERROR("tcp_reasm: out of memory allocating segment");
        return NULL;
    }
    seg->seq     = seq;
    seg->seq_len = seq_len;
    seg->data_len = data_len;
    seg->flags   = flags;
    seg->next    = NULL;
    if (data != NULL && data_len > 0) {
        uint16_t copy_len = data_len < TCP_SEG_MAX_DATA ? data_len : TCP_SEG_MAX_DATA;
        memcpy(seg->data, data, copy_len);
        seg->data_len = copy_len;
    }
    return seg;
}

/*
 * segment_free_chain — 释放整个段链表
 */
static void segment_free_chain(struct tcp_segment *head)
{
    while (head != NULL) {
        struct tcp_segment *next = head->next;
        free(head);
        g_seg_total--;
        head = next;
    }
}

/*
 * stream_alloc — 分配并初始化一个新流
 */
static struct tcp_stream *stream_alloc(const struct tcp_key *key)
{
    struct tcp_stream *s = calloc(1, sizeof(struct tcp_stream));
    if (s == NULL) {
        LOG_ERROR("tcp_reasm: out of memory allocating stream");
        return NULL;
    }
    s->key            = *key;
    s->state          = TCP_STATE_CLOSED;
    s->client_isn     = 0;
    s->server_isn     = 0;
    s->client_next_seq = 0;
    s->server_next_seq = 0;
    s->segments       = NULL;
    s->seg_count      = 0;
    /* ---- 重组缓冲区懒初始化为 NULL ---- */
    s->reasm_buf      = NULL;
    s->reasm_len      = 0;
    s->reasm_cap      = 0;
    s->reasm_next_seq = 0;
    s->reasm_active   = 0;
    s->dup_count      = 0;
    s->retrans_count  = 0;
    s->overlap_count  = 0;
    s->ooo_count      = 0;
    s->next           = NULL;
    return s;
}

/*
 * stream_free_one — 释放单个流及其所有资源
 */
static void stream_free_one(struct tcp_stream *stream)
{
    if (stream == NULL) return;
    segment_free_chain(stream->segments);
    if (stream->reasm_buf != NULL)
        free(stream->reasm_buf);
    free(stream);
    g_stream_count--;
}

/* ============================================================
 *  哈希表操作（内部）
 * ============================================================ */

/*
 * stream_lookup — 在哈希表中查找流
 *
 * 返回匹配流的指针，未找到返回 NULL。
 */
static struct tcp_stream *stream_lookup(const struct tcp_key *key)
{
    size_t idx = hash_key(key);
    struct tcp_stream *s = g_buckets[idx];
    while (s != NULL) {
        if (key_equal(&s->key, key))
            return s;
        s = s->next;
    }
    return NULL;
}

/*
 * stream_insert — 将流插入哈希表
 *
 * 调用方保证 key 不重复。
 */
static int stream_insert(struct tcp_stream *stream)
{
    size_t idx = hash_key(&stream->key);
    stream->next = g_buckets[idx];
    g_buckets[idx] = stream;
    g_stream_count++;
    return 0;
}

/*
 * stream_find_or_create — 查找或创建流
 *
 * 先在哈希表中按 key 查找；找到则返回。
 * 未找到时创建新流并插入哈希表。
 * 还会尝试使用交换后的 key（反向流）查找，以处理可能的
 * 客户端/服务端方向不一致问题。
 */
static struct tcp_stream *stream_find_or_create(const struct tcp_key *key)
{
    struct tcp_stream *s = stream_lookup(key);
    if (s != NULL)
        return s;

    /* 尝试交换方向后查找（处理首包方向不确定的情况） */
    struct tcp_key swapped;
    key_swap(&swapped, key);
    s = stream_lookup(&swapped);
    if (s != NULL)
        return s;

    /* 都没找到 → 创建新流 */
    s = stream_alloc(key);
    if (s == NULL)
        return NULL;

    if (stream_insert(s) != 0) {
        free(s);
        return NULL;
    }
    return s;
}

/* ============================================================
 *  段插入（按 SEQ 排序 + 重叠处理）
 * ============================================================ */

/*
 * segment_insert_sorted — 将新段按 SEQ 升序插入流中
 *
 * 处理各种重叠情况：
 *   - 完全重复 → 丢弃，返回 TCP_INSERT_DUP
 *   - 首部重叠 → 截断新段的覆盖部分
 *   - 完全覆盖已有段 → 移除已有，保留新段
 *   - 无重叠 → 正常插入
 *
 * 返回： 0 成功，-1 失败，-2 完全重复，-3 部分重传
 */
static int segment_insert_sorted(struct tcp_stream *stream,
                                  uint32_t seq, uint32_t seq_len,
                                  const uint8_t *data, uint16_t data_len,
                                  uint8_t flags)
{
    /* 没有载荷则不插入 */
    if (data_len == 0 && !(flags & (TCP_FLAG_SYN | TCP_FLAG_FIN)))
        return 0;
    if (seq_len == 0)
        return 0;

    /* ---- 局部变量，在遍历中逐步调整 ---- */
    uint32_t cur_seq     = seq;
    uint32_t cur_seq_len = seq_len;
    uint16_t cur_data_len = data_len;
    const uint8_t *cur_data = data;
    int result = 0;

    /* ---- 遍历链表，处理重叠 ---- */
    struct tcp_segment *prev = NULL;
    struct tcp_segment *curr = stream->segments;

    while (curr != NULL) {
        uint32_t curr_end = curr->seq + curr->seq_len;
        uint32_t new_end  = cur_seq + cur_seq_len;

        if (curr_end <= cur_seq) {
            /* [===curr===] 完全在当前段之前 → 继续前进 */
            prev = curr;
            curr = curr->next;
            continue;
        }

        if (curr->seq >= new_end) {
            /* [===new===] 完全在当前段之前 → 无更多重叠 */
            break;
        }

        /* ======== 存在重叠 ======== */

        if (curr->seq == cur_seq) {
            /* 相同起始 SEQ */
            if (cur_seq_len <= curr->seq_len) {
                /* 新段完全被已有段覆盖 → 完全重复或更短重传 */
                stream->dup_count++;
                return TCP_INSERT_DUP;
            }
            /* 新段比已有段长 → 追加尾部未覆盖数据 */
            uint32_t covered = curr->seq_len;
            cur_seq     += covered;
            cur_seq_len -= covered;
            /* 调整数据指针 */
            if (cur_data_len > (uint16_t)covered) {
                cur_data     += (uint16_t)covered;
                cur_data_len -= (uint16_t)covered;
            } else {
                cur_data_len = 0;
            }
            /* 移除已完全覆盖的 curr */
            struct tcp_segment *to_rm = curr;
            curr = curr->next;
            if (prev)
                prev->next = curr;
            else
                stream->segments = curr;
            free(to_rm);
            g_seg_total--;
            stream->seg_count--;
            stream->retrans_count++;
            result = TCP_INSERT_RETRANSMIT;
            /* 继续检查下一个段 */
            continue;
        }

        if (curr->seq < cur_seq) {
            /* curr 在新段之前开始 */
            if (curr_end >= new_end) {
                /* 新段完全被 curr 覆盖 */
                stream->dup_count++;
                return TCP_INSERT_DUP;
            }
            /* 新段尾部超出 curr → 截断新段头部 */
            uint32_t covered = curr_end - cur_seq;
            cur_seq     += covered;
            cur_seq_len -= covered;
            if (cur_data_len > (uint16_t)covered) {
                cur_data     += (uint16_t)covered;
                cur_data_len -= (uint16_t)covered;
            } else {
                cur_data_len = 0;
            }
            result = TCP_INSERT_OVERLAP;
            /* 前进到 next，继续检查 */
            prev = curr;
            curr = curr->next;
            continue;
        }

        if (curr->seq > cur_seq) {
            /* 新段在 curr 之前开始 */
            if (new_end <= curr_end) {
                /* 新段结束在 curr 内部 → 截断新段尾部 */
                cur_seq_len = curr->seq - cur_seq;
                if (cur_data_len > cur_seq_len)
                    cur_data_len = (uint16_t)cur_seq_len;
                result = TCP_INSERT_OVERLAP;
                break;  /* 无更多重叠 */
            }
            /* 新段完全覆盖 curr → 移除 curr */
            struct tcp_segment *to_rm = curr;
            curr = curr->next;
            if (prev)
                prev->next = curr;
            else
                stream->segments = curr;
            free(to_rm);
            g_seg_total--;
            stream->seg_count--;
            stream->overlap_count++;
            result = TCP_INSERT_OVERLAP;
            /* 新段不变，继续检查下一个 */
            continue;
        }

        /* 不应到达这里，防御性前进 */
        prev = curr;
        curr = curr->next;
    }

    /* ---- 处理完后无有效数据的情况 ---- */
    if (cur_seq_len == 0)
        return result;
    if (cur_data_len == 0 && !(flags & (TCP_FLAG_SYN | TCP_FLAG_FIN)))
        return result;

    /* ---- 分配并插入 ---- */
    uint16_t final_data_len = cur_data_len;
    if (final_data_len > cur_seq_len)
        final_data_len = (uint16_t)cur_seq_len;

    struct tcp_segment *new_seg = segment_alloc(cur_seq, cur_seq_len,
                                                 cur_data, final_data_len,
                                                 flags);
    if (new_seg == NULL)
        return -1;

    /* 插入到 prev 和 curr 之间 */
    if (prev == NULL) {
        new_seg->next = stream->segments;
        stream->segments = new_seg;
    } else {
        new_seg->next = curr;
        prev->next = new_seg;
    }
    stream->seg_count++;
    g_seg_total++;

    /* 记录是否是乱序（插在非末尾位置 且 链表非空） */
    if (curr != NULL && stream->seg_count > 1) {
        stream->ooo_count++;
    }

    return result;
}

/* ============================================================
 *  连续重组
 * ============================================================ */

/*
 * reasm_buf_ensure — 确保重组缓冲区至少能容纳 need 字节
 *
 * 返回 0 成功，-1 内存不足。
 */
static int reasm_buf_ensure(struct tcp_stream *stream, uint32_t need)
{
    if (stream->reasm_cap >= need)
        return 0;

    /* 不超过最大限制 */
    if (need > REASM_BUF_MAX_SIZE) {
        LOG_WARN("tcp_reasm: reassembly buffer would exceed max size (%u), truncating",
                 REASM_BUF_MAX_SIZE);
        need = REASM_BUF_MAX_SIZE;
    }

    uint32_t new_cap = stream->reasm_cap == 0
                           ? REASM_BUF_INIT_SIZE
                           : stream->reasm_cap;
    while (new_cap < need) {
        new_cap *= 2;
        if (new_cap > REASM_BUF_MAX_SIZE) {
            new_cap = REASM_BUF_MAX_SIZE;
            break;
        }
    }

    uint8_t *new_buf = realloc(stream->reasm_buf, new_cap);
    if (new_buf == NULL && new_cap > 0) {
        LOG_ERROR("tcp_reasm: realloc(%u) failed for reassembly buffer", new_cap);
        return -1;
    }
    stream->reasm_buf = new_buf;
    stream->reasm_cap = new_cap;
    return 0;
}

uint32_t tcp_reasm_assemble(struct tcp_stream *stream)
{
    if (stream == NULL || stream->segments == NULL)
        return 0;

    /* 如果重组未初始化，使用第一个段的首 SEQ 初始化 */
    if (!stream->reasm_active && stream->segments != NULL) {
        /* 跳过 SYN 段 */
        struct tcp_segment *first = stream->segments;
        if (first->flags & TCP_FLAG_SYN) {
            /* SYN 仅消耗 seq_len=1，无实质数据 */
            stream->reasm_next_seq = first->seq + first->seq_len;
            stream->reasm_active = 1;
            /* 移除 SYN 段 */
            stream->segments = first->next;
            free(first);
            g_seg_total--;
            stream->seg_count--;
        } else {
            stream->reasm_next_seq = first->seq;
            stream->reasm_active = 1;
        }
    }

    uint32_t total_appended = 0;

    while (stream->segments != NULL) {
        struct tcp_segment *seg = stream->segments;

        /* 检查是否连续 */
        if (seg->seq != stream->reasm_next_seq)
            break;

        /* 只拷贝实际载荷数据（SYN/FIN 占用序列号空间但不产生数据） */
        uint32_t data_to_copy = seg->data_len;
        if (data_to_copy > 0) {
            if (reasm_buf_ensure(stream, stream->reasm_len + data_to_copy) != 0)
                break;
            memcpy(stream->reasm_buf + stream->reasm_len, seg->data, data_to_copy);
            stream->reasm_len += data_to_copy;
            total_appended += data_to_copy;
        }

        /* 推进期望序列号（跳过整个 SEQ 空间，含 SYN/FIN） */
        stream->reasm_next_seq = seg->seq + seg->seq_len;

        /* 移除已处理的段 */
        stream->segments = seg->next;
        free(seg);
        g_seg_total--;
        stream->seg_count--;
    }

    return total_appended;
}

/* ============================================================
 *  以太网帧解析（内部）
 *
 *  从原始帧中提取五元组和 TCP 头字段。
 *  支持 IPv4、IPv6（含扩展头遍历）。
 * ============================================================ */

/*
 * 提取时需要的中间结果
 */
struct tcp_pkt_info {
    struct tcp_key key;          /* 五元组 */
    uint32_t       seq;          /* TCP SEQ（主机序） */
    uint32_t       ack;          /* TCP ACK（主机序） */
    uint8_t        flags;        /* TCP 标志位 */
    uint16_t       payload_off;  /* TCP 载荷在帧中的偏移（从帧头起） */
    uint16_t       payload_len;  /* TCP 载荷长度 */
};

/*
 * parse_ipv4_pkt — 从 IPv4 包解析到 tcp_pkt_info
 *
 * pkt      — 指向 IPv4 头起始位置
 * len      — 剩余长度
 * info     — [输出] 填充的包信息
 * frame_ofs — 当前 pkt 相对于以太网帧头的偏移
 *
 * 返回：0 非 TCP 或解析完成，1 是 TCP 且 info 已填充，-1 错误
 */
static int parse_ipv4_pkt(const uint8_t *pkt, size_t len,
                           struct tcp_pkt_info *info, size_t frame_ofs)
{
    if (pkt == NULL || info == NULL)
        return -1;
    if (len < sizeof(struct ipv4_hdr))
        return -1;

    const struct ipv4_hdr *ip = (const struct ipv4_hdr *)pkt;

    /* 验证版本 */
    if (IPV4_VERSION(ip) != 4)
        return -1;

    /* 验证 IHL */
    size_t ihl = IPV4_IHL(ip);
    if (ihl < 20 || ihl > 60 || (ihl % 4) != 0)
        return -1;
    if (len < ihl)
        return -1;

    /* 总长度验证 */
    uint16_t total_len = ntohs(ip->total_len);
    if (total_len < ihl)
        return -1;
    if (total_len > len)
        total_len = (uint16_t)len;  /* 截断到缓冲区实际大小 */

    /* 非首分片跳过（不含 L4 头） */
    uint16_t frag_off = ntohs(ip->frag_off);
    if ((frag_off & 0x1FFF) != 0)
        return 0;  /* 非首分片，无 L4 信息 */

    /* 非 TCP 则提前返回但不报错 */
    if (ip->proto != IP_PROTO_TCP)
        return 0;

    /* 计算 L4 头部偏移 */
    size_t l4_off = frame_ofs + ihl;
    const uint8_t *l4 = pkt + ihl;
    size_t l4_len = (size_t)(total_len) - ihl;

    if (l4_len < sizeof(struct tcp_hdr))
        return -1;

    const struct tcp_hdr *tcp = (const struct tcp_hdr *)l4;

    size_t tcp_hdr_len = TCP_DATA_OFFSET(tcp);
    if (tcp_hdr_len < TCP_HDR_MIN_LEN || tcp_hdr_len > 60 || (tcp_hdr_len % 4) != 0)
        return -1;
    if (l4_len < tcp_hdr_len)
        return -1;

    /* 填充五元组 */
    info->key.af       = TCP_KEY_AF_IPV4;
    info->key.src.ipv4 = ip->src;
    info->key.dst.ipv4 = ip->dst;
    info->key.src_port = tcp->src_port;
    info->key.dst_port = tcp->dst_port;
    info->key.proto    = IP_PROTO_TCP;

    /* 填充 TCP 字段（转为主机序） */
    info->seq   = ntohl(tcp->seq);
    info->ack   = ntohl(tcp->ack);
    info->flags = tcp->flags;

    /* 载荷偏移和长度 */
    info->payload_off = (uint16_t)(l4_off + tcp_hdr_len);
    info->payload_len = (uint16_t)(l4_len - tcp_hdr_len);

    return 1;  /* 成功，是 TCP */
}

/*
 * parse_ipv6_pkt — 从 IPv6 包解析到 tcp_pkt_info
 *
 * 与 parse_ipv4_pkt 类似，但需要遍历 IPv6 扩展头链。
 */
static int parse_ipv6_pkt(const uint8_t *pkt, size_t len,
                           struct tcp_pkt_info *info, size_t frame_ofs)
{
    if (pkt == NULL || info == NULL)
        return -1;
    if (len < sizeof(struct ipv6_hdr))
        return -1;

    const struct ipv6_hdr *ip6 = (const struct ipv6_hdr *)pkt;

    /* 验证版本 */
    if (IPV6_VERSION(ip6) != 6)
        return -1;

    uint16_t plen = ntohs(ip6->payload_len);
    uint8_t next_hdr = ip6->next_hdr;
    const uint8_t *l4 = pkt + sizeof(struct ipv6_hdr);
    size_t remaining = plen;
    size_t buf_remaining = len - sizeof(struct ipv6_hdr);
    if (remaining > buf_remaining)
        remaining = buf_remaining;

    int is_fragmented = 0;
    int ext_hdr_count = 0;
    const int MAX_EXT_HDR = 64;

    /* 遍历扩展头直到找到 TCP 或到达传输层 */
    while (next_hdr != IP_PROTO_TCP &&
           next_hdr != IP_PROTO_UDP &&
           next_hdr != IP_PROTO_ICMP &&
           next_hdr != IP_PROTO_ICMPV6 &&
           next_hdr != IPV6_NEXT_NONE) {

        if (ext_hdr_count >= MAX_EXT_HDR || remaining < 2)
            return -1;

        size_t eh_len = 0;
        uint8_t hdr_type = next_hdr;
        next_hdr = l4[0];

        switch (hdr_type) {
        case IPV6_NEXT_HOPOPT:
        case IPV6_NEXT_ROUTING:
        case IPV6_NEXT_DSTOPT: {
            uint8_t hdr_ext_len = l4[1];
            eh_len = ((size_t)hdr_ext_len + 1) * 8;
            break;
        }
        case IPV6_NEXT_FRAGMENT: {
            eh_len = 8;
            if (remaining >= 8) {
                uint16_t raw;
                memcpy(&raw, l4 + 2, 2);
                uint16_t frag_flags = ntohs(raw);
                uint16_t frag_ofs = frag_flags & 0xFFF8;
                uint8_t  frag_mf  = frag_flags & 0x0001;
                if (frag_ofs != 0 || frag_mf)
                    is_fragmented = 1;
            }
            break;
        }
        case IPV6_NEXT_AH: {
            uint8_t hdr_ext_len = l4[1];
            eh_len = ((size_t)hdr_ext_len + 2) * 4;
            break;
        }
        case IPV6_NEXT_ESP:
            /* ESP 无 next_hdr，终止 */
            return 0;
        default:
            /* 未知扩展头，终止遍历 */
            goto check_tcp;
        }

        if (eh_len == 0 || eh_len > remaining)
            return -1;

        l4 += eh_len;
        remaining -= eh_len;
        ext_hdr_count++;
    }

check_tcp:

    if (next_hdr != IP_PROTO_TCP || is_fragmented)
        return 0;

    if (remaining < sizeof(struct tcp_hdr))
        return -1;

    const struct tcp_hdr *tcp = (const struct tcp_hdr *)l4;
    size_t tcp_hdr_len = TCP_DATA_OFFSET(tcp);
    if (tcp_hdr_len < TCP_HDR_MIN_LEN || tcp_hdr_len > 60 || (tcp_hdr_len % 4) != 0)
        return -1;
    if (remaining < tcp_hdr_len)
        return -1;

    /* 填充五元组 */
    info->key.af = TCP_KEY_AF_IPV6;
    memcpy(info->key.src.ipv6, ip6->src, 16);
    memcpy(info->key.dst.ipv6, ip6->dst, 16);
    info->key.src_port = tcp->src_port;
    info->key.dst_port = tcp->dst_port;
    info->key.proto    = IP_PROTO_TCP;

    /* 填充 TCP 字段 */
    info->seq   = ntohl(tcp->seq);
    info->ack   = ntohl(tcp->ack);
    info->flags = tcp->flags;

    /* 载荷偏移 */
    size_t l4_off_in_frame = frame_ofs + (size_t)(l4 - pkt);
    info->payload_off = (uint16_t)(l4_off_in_frame + tcp_hdr_len);
    info->payload_len = (uint16_t)(remaining - tcp_hdr_len);

    return 1;
}

/* ============================================================
 *  公共接口实现
 * ============================================================ */

void tcp_reasm_init(void)
{
    memset(g_buckets, 0, sizeof(g_buckets));
    g_stream_count = 0;
    g_seg_total    = 0;
    g_initialized  = 1;
    LOG_INFO("TCP reassembly initialized (hash size=%d)", REASM_HASH_SIZE);
}

void tcp_reasm_destroy(void)
{
    if (!g_initialized)
        return;

    /* 释放所有流及段 */
    for (size_t i = 0; i < REASM_HASH_SIZE; i++) {
        struct tcp_stream *s = g_buckets[i];
        while (s != NULL) {
            struct tcp_stream *next = s->next;
            stream_free_one(s);
            s = next;
        }
        g_buckets[i] = NULL;
    }

    LOG_INFO("TCP reassembly destroyed (streams freed=%d, segments freed=%d)",
             g_stream_count, g_seg_total);
    g_stream_count = 0;
    g_seg_total    = 0;
    g_initialized  = 0;
}

int tcp_reasm_extract_key(const uint8_t *pkt, size_t len, struct tcp_key *key)
{
    if (pkt == NULL || key == NULL)
        return -1;
    if (len < ETH_HDR_LEN)
        return -1;

    const struct eth_hdr *eth = (const struct eth_hdr *)pkt;
    uint16_t ethertype = ntohs(eth->type);
    const uint8_t *payload = pkt + ETH_HDR_LEN;
    size_t plen = len - ETH_HDR_LEN;

    /* 处理 VLAN 标签 */
    if (ethertype == ETH_TYPE_VLAN) {
        if (plen < 4)
            return -1;
        payload += 4;
        plen -= 4;
        if (plen < 2)
            return -1;
        uint16_t inner_type;
        memcpy(&inner_type, payload, 2);
        ethertype = ntohs(inner_type);
        payload += 2;
        plen -= 2;
    }

    struct tcp_pkt_info info;
    memset(&info, 0, sizeof(info));
    int ret;

    if (ethertype == ETH_TYPE_IPV4) {
        ret = parse_ipv4_pkt(payload, plen, &info, ETH_HDR_LEN);
    } else if (ethertype == ETH_TYPE_IPV6) {
        ret = parse_ipv6_pkt(payload, plen, &info, ETH_HDR_LEN);
    } else {
        return -1;  /* 非 IP 包 */
    }

    if (ret != 1)
        return -1;  /* 非 TCP 或解析失败 */

    *key = info.key;
    return 0;
}

struct tcp_stream *tcp_reasm_get_stream(const struct tcp_key *key)
{
    if (key == NULL || !g_initialized)
        return NULL;
    return stream_lookup(key);
}

int tcp_reasm_insert(const uint8_t *pkt, size_t len)
{
    if (pkt == NULL || !g_initialized) {
        LOG_ERROR("tcp_reasm_insert: invalid params or not initialized");
        return -1;
    }
    if (len < ETH_HDR_LEN) {
        LOG_ERROR("tcp_reasm_insert: frame too short (%zu)", len);
        return -1;
    }

    /* === 1. 解析以太网头 === */
    const struct eth_hdr *eth = (const struct eth_hdr *)pkt;
    uint16_t ethertype = ntohs(eth->type);
    const uint8_t *payload = pkt + ETH_HDR_LEN;
    size_t plen = len - ETH_HDR_LEN;

    /* 处理 VLAN 标签 */
    if (ethertype == ETH_TYPE_VLAN) {
        if (plen < 4) return -1;
        payload += 4;
        plen -= 4;
        if (plen < 2) return -1;
        uint16_t inner_type;
        memcpy(&inner_type, payload, 2);
        ethertype = ntohs(inner_type);
        payload += 2;
        plen -= 2;
    }

    /* === 2. 解析 IP + TCP，提取信息 === */
    struct tcp_pkt_info info;
    memset(&info, 0, sizeof(info));
    int ret;

    if (ethertype == ETH_TYPE_IPV4) {
        ret = parse_ipv4_pkt(payload, plen, &info, ETH_HDR_LEN);
    } else if (ethertype == ETH_TYPE_IPV6) {
        ret = parse_ipv6_pkt(payload, plen, &info, ETH_HDR_LEN);
    } else {
        return -1;  /* 非 IP 包，忽略 */
    }

    if (ret != 1) {
        /* 非 TCP 或解析失败 */
        return (ret == -1) ? -1 : 0;
    }

    /* === 3. 查找或创建流 === */
    struct tcp_stream *stream = stream_find_or_create(&info.key);
    if (stream == NULL) {
        LOG_ERROR("tcp_reasm_insert: failed to find/create stream");
        return -1;
    }

    /* === 4. 判断方向：通过 src/dst 与流中 key 比对 === */
    int is_from_client;
    if (key_equal(&stream->key, &info.key)) {
        is_from_client = 1;  /* 原始方向 = 客户端→服务端 */
    } else {
        /* 检查是否为反向包 */
        struct tcp_key swapped;
        key_swap(&swapped, &stream->key);
        if (key_equal(&swapped, &info.key)) {
            is_from_client = 0;  /* 服务端→客户端 */
        } else {
            LOG_WARN("tcp_reasm: packet direction mismatch, treating as client");
            is_from_client = 1;
        }
    }

    /* === 5. 运行状态机 === */
    tcp_state_machine(stream, info.flags, info.seq, info.ack, is_from_client);

    /* === 6. 插入载荷段（含重叠处理） === */
    int insert_result = 0;
    if (info.payload_len > 0 || (info.flags & (TCP_FLAG_SYN | TCP_FLAG_FIN))) {
        /* 计算该段在数据流中的 SEQ 长度 */
        uint32_t seq_len = info.payload_len;
        if (info.flags & TCP_FLAG_SYN) seq_len++;
        if (info.flags & TCP_FLAG_FIN) seq_len++;

        const uint8_t *payload_data = NULL;
        uint16_t data_len = 0;
        if (info.payload_len > 0) {
            payload_data = pkt + info.payload_off;
            data_len = info.payload_len;
        }

        insert_result = segment_insert_sorted(stream, info.seq, seq_len,
                                               payload_data, data_len, info.flags);
    }

    return insert_result;
}

void tcp_state_machine(struct tcp_stream *stream, uint8_t flags,
                       uint32_t seq, uint32_t ack, int is_from_client)
{
    (void)ack;  /* 保留参数，后续状态机扩展时使用 */

    if (stream == NULL)
        return;

    tcp_state_t old_state = stream->state;

    /* RST 直接关闭 */
    if (flags & TCP_FLAG_RST) {
        stream->state = TCP_STATE_CLOSED;
        LOG_INFO("tcp_reasm: RST received, %s -> CLOSED",
                 tcp_state_name(old_state));
        return;
    }

    switch (stream->state) {

    case TCP_STATE_CLOSED:
        /* 从客户端收到 SYN → SYN_RCVD */
        if ((flags & TCP_FLAG_SYN) && !(flags & TCP_FLAG_ACK) && is_from_client) {
            stream->client_isn = seq;
            stream->client_next_seq = seq + 1;
            stream->state = TCP_STATE_SYN_RCVD;
            LOG_INFO("tcp_reasm: SYN (ISN=0x%08x), CLOSED -> SYN_RCVD", seq);
        }
        break;

    case TCP_STATE_SYN_RCVD:
        if (flags & TCP_FLAG_SYN && flags & TCP_FLAG_ACK && !is_from_client) {
            /* 服务端 SYN+ACK */
            stream->server_isn = seq;
            stream->server_next_seq = seq + 1;
            stream->state = TCP_STATE_ESTABLISHED;
            LOG_INFO("tcp_reasm: SYN+ACK (ISN=0x%08x), SYN_RCVD -> ESTABLISHED", seq);
        } else if (flags & TCP_FLAG_SYN && is_from_client) {
            /* 重传的 SYN */
            stream->client_isn = seq;
            stream->client_next_seq = seq + 1;
            LOG_INFO("tcp_reasm: retransmit SYN (ISN=0x%08x)", seq);
        }
        break;

    case TCP_STATE_ESTABLISHED:
        /* 收到 FIN → 单向关闭 */
        if (flags & TCP_FLAG_FIN) {
            stream->state = TCP_STATE_FIN_RCVD;
            LOG_INFO("tcp_reasm: FIN, ESTABLISHED -> FIN_RCVD");
        }
        /* 更新期望的 SEQ */
        if (is_from_client && seq >= stream->client_next_seq) {
            stream->client_next_seq = seq + 1;
        } else if (!is_from_client && seq >= stream->server_next_seq) {
            stream->server_next_seq = seq + 1;
        }
        break;

    case TCP_STATE_FIN_RCVD:
        /* 另一个方向也收到 FIN → CLOSING */
        if (flags & TCP_FLAG_FIN) {
            stream->state = TCP_STATE_CLOSING;
            LOG_INFO("tcp_reasm: second FIN, FIN_RCVD -> CLOSING");
        }
        break;

    case TCP_STATE_CLOSING:
        /* 可以在这里实现 TIME_WAIT 逻辑（留待日后扩展） */
        break;

    default:
        break;
    }
}

const uint8_t *tcp_reasm_get_data(struct tcp_stream *stream, uint32_t *len)
{
    if (stream == NULL || len == NULL) {
        if (len) *len = 0;
        return NULL;
    }

    /* 先尝试组装更多数据 */
    tcp_reasm_assemble(stream);

    *len = stream->reasm_len;
    if (stream->reasm_len == 0 || stream->reasm_buf == NULL)
        return NULL;

    return stream->reasm_buf;
}

void tcp_reasm_get_stream_stats(struct tcp_stream *stream,
                                uint32_t *dup, uint32_t *retrans,
                                uint32_t *overlap, uint32_t *ooo)
{
    if (stream == NULL) {
        if (dup)     *dup     = 0;
        if (retrans) *retrans = 0;
        if (overlap) *overlap = 0;
        if (ooo)     *ooo     = 0;
        return;
    }
    if (dup)     *dup     = stream->dup_count;
    if (retrans) *retrans = stream->retrans_count;
    if (overlap) *overlap = stream->overlap_count;
    if (ooo)     *ooo     = stream->ooo_count;
}

int tcp_reasm_stream_count(void)
{
    return g_stream_count;
}

int tcp_reasm_segment_count(void)
{
    return g_seg_total;
}
