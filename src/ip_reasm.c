#include "ip_reasm.h"
#include "common.h"
#include "protocol.h"

/*
 * ip_reasm.c — IP 分片重组实现
 *
 * 支持 IPv4 与 IPv6 分片的缓存、排序、重组。
 *
 * IPv4 分片识别：
 *   frag_off & 0x1FFF != 0  或者 frag_off & MF 标志
 *
 * IPv6 分片识别：
 *   Fragment 扩展头 (next_hdr=44)
 *
 * 分片键 (IPv4) = (src, dst, ident, proto)
 * 分片键 (IPv6) = (src, dst, ident, next_hdr)
 *
 * 重组完成后，调用方接收一个完整 IP 包（含 IP 头）的缓冲区。
 */

/* ============================================================
 *  内部哈希表
 * ============================================================ */

static struct ip_frag_stream *g_frag_buckets[IP_FRAG_HASH_SIZE];
static int g_initialized = 0;
static int g_stream_count = 0;
static int g_frag_total = 0;

/* ============================================================
 *  哈希与键操作
 * ============================================================ */

/* DJB2 哈希 */
static size_t frag_key_hash(const struct ip_frag_key *key)
{
    uint32_t h = 5381;
    const uint8_t *p;
    int i;

    /* 哈希源地址 */
    p = (const uint8_t *)key->src;
    for (i = 0; i < 16; i++)
        h = ((h << 5) + h) + p[i];

    /* 哈希目的地址 */
    p = (const uint8_t *)key->dst;
    for (i = 0; i < 16; i++)
        h = ((h << 5) + h) + p[i];

    /* 哈希 ident */
    p = (const uint8_t *)&key->ident;
    for (i = 0; i < 4; i++)
        h = ((h << 5) + h) + p[i];

    h = ((h << 5) + h) + key->proto;
    h = ((h << 5) + h) + key->version;

    return (size_t)(h % IP_FRAG_HASH_SIZE);
}

static int frag_key_equal(const struct ip_frag_key *a,
                           const struct ip_frag_key *b)
{
    return (memcmp(a->src, b->src, 16) == 0 &&
            memcmp(a->dst, b->dst, 16) == 0 &&
            a->ident   == b->ident &&
            a->proto   == b->proto &&
            a->version == b->version);
}

/* ============================================================
 *  分片流管理
 * ============================================================ */

static struct ip_frag_stream *frag_stream_alloc(const struct ip_frag_key *key,
                                                 const uint8_t *ip_hdr,
                                                 uint8_t ip_hdr_len)
{
    struct ip_frag_stream *fs = calloc(1, sizeof(struct ip_frag_stream));
    if (fs == NULL) {
        LOG_ERROR("ip_reasm: out of memory for frag stream");
        return NULL;
    }
    fs->key = *key;
    fs->total_data_len = 0;
    fs->received_len = 0;
    fs->frag_count = 0;
    fs->first_seen = time(NULL);
    fs->ip_hdr_len = ip_hdr_len;
    fs->fragments = NULL;
    fs->next = NULL;

    /* 复制 IP 头 */
    if (ip_hdr != NULL && ip_hdr_len > 0) {
        fs->ip_header = malloc(ip_hdr_len);
        if (fs->ip_header == NULL) {
            LOG_ERROR("ip_reasm: out of memory for IP header copy");
            free(fs);
            return NULL;
        }
        memcpy(fs->ip_header, ip_hdr, ip_hdr_len);
    } else {
        fs->ip_header = NULL;
    }

    return fs;
}

static void frag_free_chain(struct ip_frag *head)
{
    while (head != NULL) {
        struct ip_frag *next = head->next;
        if (head->data)
            free(head->data);
        free(head);
        head = next;
    }
}

static void frag_stream_free_one(struct ip_frag_stream *fs)
{
    if (fs == NULL) return;
    frag_free_chain(fs->fragments);
    if (fs->ip_header)
        free(fs->ip_header);
    free(fs);
}

static struct ip_frag_stream *frag_stream_lookup(const struct ip_frag_key *key)
{
    size_t idx = frag_key_hash(key);
    struct ip_frag_stream *fs = g_frag_buckets[idx];
    while (fs != NULL) {
        if (frag_key_equal(&fs->key, key))
            return fs;
        fs = fs->next;
    }
    return NULL;
}

static int frag_stream_insert(struct ip_frag_stream *fs)
{
    size_t idx = frag_key_hash(&fs->key);
    fs->next = g_frag_buckets[idx];
    g_frag_buckets[idx] = fs;
    g_stream_count++;
    return 0;
}

/* ============================================================
 *  分片插入
 * ============================================================ */

/*
 * frag_insert_sorted — 将分片插入流，按 offset 升序
 *
 * 处理以下情况：
 *   - 重复分片（相同 offset）→ 丢弃
 *   - 重叠分片 → 截断（保留先到的数据）
 *
 * 返回 0 成功，-1 失败。
 */
static int frag_insert_sorted(struct ip_frag_stream *fs,
                               uint16_t offset, uint16_t data_len,
                               uint8_t mf, const uint8_t *data)
{
    if (fs->frag_count >= IP_FRAG_MAX_FRAGMENTS) {
        LOG_WARN("ip_reasm: too many fragments (%u) for one stream", fs->frag_count);
        return -1;
    }

    /* 分配分片节点 */
    struct ip_frag *frag = calloc(1, sizeof(struct ip_frag));
    if (frag == NULL) {
        LOG_ERROR("ip_reasm: out of memory for frag node");
        return -1;
    }
    frag->offset   = offset;
    frag->data_len = data_len;
    frag->mf       = mf;
    frag->data     = NULL;
    frag->next     = NULL;

    if (data_len > 0) {
        frag->data = malloc(data_len);
        if (frag->data == NULL) {
            LOG_ERROR("ip_reasm: out of memory for frag data");
            free(frag);
            return -1;
        }
        memcpy(frag->data, data, data_len);
    }

    /* ======== 重叠/重复处理 ======== */
    struct ip_frag *prev = NULL;
    struct ip_frag *curr = fs->fragments;

    while (curr != NULL) {
        uint16_t curr_end = curr->offset + curr->data_len;
        uint16_t new_end  = offset + data_len;

        if (curr_end <= offset) {
            /* curr 完全在新分片之前 */
            prev = curr;
            curr = curr->next;
            continue;
        }

        if (curr->offset >= new_end) {
            /* curr 完全在新分片之后 */
            break;
        }

        /* 重叠 */
        if (curr->offset == offset) {
            /* 相同偏移 → 重复分片，丢弃新分片 */
            if (frag->data) free(frag->data);
            free(frag);
            return 0;  /* 丢弃但不报错 */
        }

        if (curr->offset < offset) {
            if (curr_end >= new_end) {
                /* 新分片完全被 curr 覆盖 */
                if (frag->data) free(frag->data);
                free(frag);
                return 0;
            }
            /* 新分片尾部超出 curr → 截断头部 */
            uint16_t covered = curr_end - offset;
            offset    += covered;
            data_len  -= covered;
            if (frag->data) {
                memmove(frag->data, frag->data + covered, data_len);
            }
            prev = curr;
            curr = curr->next;
            continue;
        }

        if (curr->offset > offset) {
            if (new_end <= curr->offset + curr->data_len) {
                /* 新分片结束在 curr 内部 → 截断尾部 */
                data_len = curr->offset - offset;
                break;
            }
            /* 新分片覆盖 curr → 移除 curr */
            struct ip_frag *to_rm = curr;
            curr = curr->next;
            if (prev) prev->next = curr;
            else      fs->fragments = curr;
            if (to_rm->data) free(to_rm->data);
            free(to_rm);
            g_frag_total--;
            fs->frag_count--;
            continue;
        }

        prev = curr;
        curr = curr->next;
    }

    if (data_len == 0) {
        if (frag->data) free(frag->data);
        free(frag);
        return 0;
    }

    /* 更新分片参数 */
    frag->offset   = offset;
    frag->data_len = data_len;

    /* 插入到 prev 和 curr 之间 */
    if (prev == NULL) {
        frag->next = fs->fragments;
        fs->fragments = frag;
    } else {
        frag->next = curr;
        prev->next = frag;
    }
    fs->frag_count++;
    g_frag_total++;

    /* 更新接收统计 */
    fs->received_len += data_len;

    return 0;
}

/* ============================================================
 *  重组检查与执行
 * ============================================================ */

/*
 * frag_check_complete — 检查分片流是否已完整接收
 *
 * 条件：
 *   - 第一个分片的 offset == 0
 *   - 最后一个分片的 mf == 0
 *   - 分片之间无间隔 (offset 连续)
 *
 * 返回 1 表示完整，0 表示不完整。
 */
static int frag_check_complete(struct ip_frag_stream *fs)
{
    if (fs->fragments == NULL)
        return 0;

    /* 第一个分片必须从 offset 0 开始 */
    if (fs->fragments->offset != 0)
        return 0;

    /* 最后一个分片必须 MF=0 */
    struct ip_frag *last = fs->fragments;
    while (last->next != NULL)
        last = last->next;
    if (last->mf)
        return 0;

    /* 检查连续性 */
    uint16_t expected_offset = 0;
    struct ip_frag *f = fs->fragments;
    while (f != NULL) {
        if (f->offset != expected_offset)
            return 0;
        expected_offset += f->data_len;
        f = f->next;
    }

    return 1;
}

/*
 * frag_do_reassemble — 执行重组，输出完整 IP 包
 *
 * 返回 0 成功，-1 失败。
 */
static int frag_do_reassemble(struct ip_frag_stream *fs,
                               uint8_t **out_buf, uint16_t *out_len)
{
    /* 计算总数据长度 */
    uint32_t total_data = 0;
    struct ip_frag *f = fs->fragments;
    while (f != NULL) {
        total_data += f->data_len;
        f = f->next;
    }

    if (total_data == 0 || total_data > IP_REASM_MAX_SIZE) {
        LOG_ERROR("ip_reasm: invalid reassembled size %u", total_data);
        return -1;
    }

    uint32_t total_pkt_len = fs->ip_hdr_len + total_data;
    if (total_pkt_len > IP_REASM_MAX_SIZE) {
        LOG_ERROR("ip_reasm: reassembled packet too large %u", total_pkt_len);
        return -1;
    }

    uint8_t *buf = malloc(total_pkt_len);
    if (buf == NULL) {
        LOG_ERROR("ip_reasm: out of memory for reassembled packet");
        return -1;
    }

    /* 复制 IP 头 */
    if (fs->ip_header && fs->ip_hdr_len > 0) {
        memcpy(buf, fs->ip_header, fs->ip_hdr_len);
    }

    /* 复制分片数据 */
    uint16_t data_offset = 0;
    f = fs->fragments;
    while (f != NULL) {
        if (f->data && f->data_len > 0) {
            memcpy(buf + fs->ip_hdr_len + f->offset, f->data, f->data_len);
        }
        data_offset += f->data_len;
        f = f->next;
    }

    /* 修正 IPv4 头字段 */
    if (fs->key.version == 4) {
        struct ipv4_hdr *ip = (struct ipv4_hdr *)buf;
        ip->total_len = htons(total_pkt_len);
        ip->frag_off = htons(0x0000);  /* 清除分片标志和偏移 */
        /* 校验和置零后重新计算 */
        ip->checksum = 0;
        /* 简单的 IP 校验和 */
        uint32_t sum = 0;
        for (int i = 0; i < (int)(fs->ip_hdr_len); i += 2) {
            uint16_t word;
            memcpy(&word, buf + i, 2);
            sum += ntohs(word);
        }
        while (sum >> 16)
            sum = (sum & 0xFFFF) + (sum >> 16);
        ip->checksum = htons(~sum & 0xFFFF);
    }

    /* 修正 IPv6 头字段 */
    if (fs->key.version == 6) {
        struct ipv6_hdr *ip6 = (struct ipv6_hdr *)buf;
        ip6->payload_len = htons(total_data);
    }

    *out_buf = buf;
    *out_len = total_pkt_len;
    return 0;
}

/* ============================================================
 *  从以太网帧中提取分片信息（IPv4）
 * ============================================================ */

/*
 * extract_ipv4_frag — 从 IPv4 包提取分片信息
 *
 * 返回 -1 错误，0 非分片或不可重组，1 是分片且提取成功。
 */
static int extract_ipv4_frag(const uint8_t *pkt, size_t len,
                              struct ip_frag_key *key,
                              uint16_t *offset, uint16_t *data_len,
                              uint8_t *mf, const uint8_t **frag_data,
                              const uint8_t **ip_hdr, uint8_t *ip_hdr_len)
{
    if (len < sizeof(struct ipv4_hdr) + sizeof(struct eth_hdr))
        return -1;

    const struct ipv4_hdr *ip = (const struct ipv4_hdr *)pkt;

    if (IPV4_VERSION(ip) != 4)
        return -1;

    size_t ihl = IPV4_IHL(ip);
    if (ihl < 20 || ihl > 60)
        return -1;
    if (len < ihl + sizeof(struct eth_hdr))
        return -1;

    uint16_t frag_off_ntoh = ntohs(ip->frag_off);
    uint16_t frag_ofs = frag_off_ntoh & 0x1FFF; /* 以 8 字节为单位 */
    uint8_t  mf_flag  = (frag_off_ntoh & 0x2000) ? 1 : 0;

    /* 非分片（offset=0 且 MF=0） */
    if (frag_ofs == 0 && !mf_flag)
        return 0;

    /* 计算数据部分 */
    uint16_t total_len = ntohs(ip->total_len);
    if (total_len < ihl)
        return -1;

    *offset   = frag_ofs * 8;  /* 转为字节 */
    *data_len = (uint16_t)(total_len - ihl);
    *mf       = mf_flag;
    *frag_data = (const uint8_t *)(ip) + ihl;

    /* 构建分片键 */
    key->version = 4;
    memset(key->src, 0, 16);
    memset(key->dst, 0, 16);
    key->src[0] = ip->src;
    key->dst[0] = ip->dst;
    key->ident  = ntohs(ip->ident);
    key->proto  = ip->proto;

    /* 保存 IP 头副本 */
    *ip_hdr     = (const uint8_t *)ip;
    *ip_hdr_len = (uint8_t)ihl;

    return 1;
}

/*
 * extract_ipv6_frag — 从 IPv6 包提取分片信息
 *
 * 遍历扩展头链找到 Fragment 头。
 */
static int extract_ipv6_frag(const uint8_t *pkt, size_t len,
                              struct ip_frag_key *key,
                              uint16_t *offset, uint16_t *data_len,
                              uint8_t *mf, const uint8_t **frag_data,
                              const uint8_t **ip_hdr, uint8_t *ip_hdr_len)
{
    if (len < sizeof(struct ipv6_hdr) + sizeof(struct eth_hdr))
        return -1;
    if (len < sizeof(struct eth_hdr))
        return -1;

    /* 跳过以太网头，指向 IPv6 头 */
    const uint8_t *ipv6_start = pkt;
    if (len < sizeof(struct ipv6_hdr))
        return -1;

    const struct ipv6_hdr *ip6 = (const struct ipv6_hdr *)ipv6_start;
    if (IPV6_VERSION(ip6) != 6)
        return -1;

    uint16_t plen = ntohs(ip6->payload_len);
    uint8_t next_hdr = ip6->next_hdr;
    const uint8_t *l4 = ipv6_start + sizeof(struct ipv6_hdr);
    size_t remaining = plen;
    size_t buf_remaining = len - sizeof(struct ipv6_hdr);
    if (remaining > buf_remaining)
        remaining = buf_remaining;

    uint8_t frag_next_hdr = 0;
    int found_frag = 0;
    int ext_hdr_count = 0;
    const int MAX_EXT_HDR = 64;

    while (next_hdr != IPV6_NEXT_NONE && found_frag == 0) {
        if (ext_hdr_count >= MAX_EXT_HDR || remaining < 2)
            return -1;

        uint8_t hdr_type = next_hdr;

        switch (hdr_type) {
        case IPV6_NEXT_HOPOPT:
        case IPV6_NEXT_ROUTING:
        case IPV6_NEXT_DSTOPT: {
            uint8_t hdr_ext_len = l4[1];
            size_t eh_len = ((size_t)hdr_ext_len + 1) * 8;
            if (eh_len > remaining) return -1;
            next_hdr = l4[0];
            l4 += eh_len;
            remaining -= eh_len;
            ext_hdr_count++;
            break;
        }
        case IPV6_NEXT_FRAGMENT: {
            if (remaining < 8) return -1;
            frag_next_hdr = l4[0];
            uint16_t raw;
            memcpy(&raw, l4 + 2, 2);
            uint16_t frag_flags = ntohs(raw);
            *offset = (frag_flags & 0xFFF8);  /* 13 bits, 8-byte units → bytes */
            *mf     = (frag_flags & 0x0001) ? 1 : 0;
            uint32_t ident_raw;
            memcpy(&ident_raw, l4 + 4, 4);
            key->ident = ntohl(ident_raw);

            /* 数据从 Fragment 头之后开始 */
            const uint8_t *after_frag = l4 + 8;
            size_t after_len = (remaining > 8) ? remaining - 8 : 0;
            *frag_data = after_frag;
            *data_len = (uint16_t)after_len;

            found_frag = 1;
            break;
        }
        case IPV6_NEXT_AH: {
            uint8_t hdr_ext_len = l4[1];
            size_t eh_len = ((size_t)hdr_ext_len + 2) * 4;
            if (eh_len > remaining) return -1;
            next_hdr = l4[0];
            l4 += eh_len;
            remaining -= eh_len;
            ext_hdr_count++;
            break;
        }
        case IPV6_NEXT_ESP:
            return 0;
        default:
            return 0;
        }
    }

    if (!found_frag)
        return 0;

    /* 非分片检查 */
    if (*offset == 0 && *mf == 0)
        return 0;

    /* 构建键 */
    key->version = 6;
    memcpy(key->src, ip6->src, 16);
    memcpy(key->dst, ip6->dst, 16);
    key->proto = frag_next_hdr;

    /* 保存 IPv6 头 */
    *ip_hdr     = ipv6_start;
    *ip_hdr_len = sizeof(struct ipv6_hdr);

    return 1;
}

/* ============================================================
 *  公共 API
 * ============================================================ */

void ip_reasm_init(void)
{
    memset(g_frag_buckets, 0, sizeof(g_frag_buckets));
    g_stream_count = 0;
    g_frag_total = 0;
    g_initialized = 1;
    LOG_INFO("IP fragment reassembly initialized (hash size=%d)", IP_FRAG_HASH_SIZE);
}

void ip_reasm_destroy(void)
{
    if (!g_initialized) return;

    for (size_t i = 0; i < IP_FRAG_HASH_SIZE; i++) {
        struct ip_frag_stream *fs = g_frag_buckets[i];
        while (fs != NULL) {
            struct ip_frag_stream *next = fs->next;
            frag_stream_free_one(fs);
            fs = next;
        }
        g_frag_buckets[i] = NULL;
    }

    LOG_INFO("IP fragment reassembly destroyed (streams=%d, fragments=%d)",
             g_stream_count, g_frag_total);
    g_stream_count = 0;
    g_frag_total = 0;
    g_initialized = 0;
}

/*
 * ip_reasm_insert — 主入口
 *
 * 流程：
 *   1. 解析以太网帧，判断 EtherType
 *   2. 提取 IP 分片信息
 *   3. 查找或创建分片流
 *   4. 插入分片
 *   5. 检查重组完成
 *   6. 若完成则重组输出
 */
int ip_reasm_insert(const uint8_t *pkt, size_t len,
                    uint8_t **out_buf, uint16_t *out_len)
{
    if (pkt == NULL || out_buf == NULL || out_len == NULL || !g_initialized)
        return -1;

    *out_buf = NULL;
    *out_len = 0;

    if (len < ETH_HDR_LEN + 20)  /* 最小以太网 + IPv4 */
        return -1;

    /* ---- 1. 解析以太网 ---- */
    const struct eth_hdr *eth = (const struct eth_hdr *)pkt;
    uint16_t ethertype = ntohs(eth->type);
    const uint8_t *payload = pkt + ETH_HDR_LEN;
    size_t plen = len - ETH_HDR_LEN;

    if (ethertype == ETH_TYPE_VLAN) {
        if (plen < 4) return -1;
        payload += 4; plen -= 4;
        if (plen < 2) return -1;
        memcpy(&ethertype, payload, 2);
        ethertype = ntohs(ethertype);
        payload += 2; plen -= 2;
    }

    /* ---- 2. 提取分片信息 ---- */
    struct ip_frag_key key;
    uint16_t offset = 0, data_len = 0;
    uint8_t mf = 0;
    const uint8_t *frag_data = NULL;
    const uint8_t *ip_hdr = NULL;
    uint8_t ip_hdr_len = 0;
    int ret;

    memset(&key, 0, sizeof(key));

    if (ethertype == ETH_TYPE_IPV4) {
        ret = extract_ipv4_frag(payload, plen, &key,
                                 &offset, &data_len,
                                 &mf, &frag_data,
                                 &ip_hdr, &ip_hdr_len);
    } else if (ethertype == ETH_TYPE_IPV6) {
        ret = extract_ipv6_frag(payload, plen, &key,
                                 &offset, &data_len,
                                 &mf, &frag_data,
                                 &ip_hdr, &ip_hdr_len);
    } else {
        return -1;  /* 非 IP 包 */
    }

    if (ret <= 0)
        return ret;  /* ret=0 非分片，ret=-1 错误 */

    /* ---- 3. 查找或创建分片流 ---- */
    struct ip_frag_stream *fs = frag_stream_lookup(&key);
    if (fs == NULL) {
        /* 创建新分片流 */
        fs = frag_stream_alloc(&key, ip_hdr, ip_hdr_len);
        if (fs == NULL)
            return -1;
        if (frag_stream_insert(fs) != 0) {
            frag_stream_free_one(fs);
            return -1;
        }
    }

    /* ---- 4. 插入分片到链表 ---- */
    if (frag_insert_sorted(fs, offset, data_len, mf, frag_data) != 0)
        return 0;  /* 插入失败，继续接受其他分片 */

    /* ---- 5. 检查是否完整 ---- */
    if (!frag_check_complete(fs))
        return 0;  /* 还不完整 */

    /* ---- 6. 重组输出 ---- */
    ret = frag_do_reassemble(fs, out_buf, out_len);
    if (ret != 0) {
        /* 重组失败，清理 */
        size_t idx = frag_key_hash(&key);
        struct ip_frag_stream **pp = &g_frag_buckets[idx];
        while (*pp != NULL) {
            if (*pp == fs) {
                *pp = fs->next;
                break;
            }
            pp = &(*pp)->next;
        }
        frag_stream_free_one(fs);
        g_stream_count--;
        return -1;
    }

    /* 重组成功，清理分片流 */
    size_t idx = frag_key_hash(&key);
    struct ip_frag_stream **pp = &g_frag_buckets[idx];
    while (*pp != NULL) {
        if (*pp == fs) {
            *pp = fs->next;
            break;
        }
        pp = &(*pp)->next;
    }
    frag_stream_free_one(fs);
    g_stream_count--;

    LOG_INFO("ip_reasm: reassembled %s frag (id=0x%x, %u bytes)",
             key.version == 4 ? "IPv4" : "IPv6",
             key.ident, *out_len);

    return 1;  /* 重组完成 */
}

int ip_reasm_cleanup(void)
{
    if (!g_initialized) return 0;

    time_t now = time(NULL);
    int cleaned = 0;

    for (size_t i = 0; i < IP_FRAG_HASH_SIZE; i++) {
        struct ip_frag_stream **pp = &g_frag_buckets[i];
        while (*pp != NULL) {
            struct ip_frag_stream *fs = *pp;
            if (difftime(now, fs->first_seen) > IP_FRAG_TIMEOUT) {
                *pp = fs->next;
                LOG_INFO("ip_reasm: timeout frag stream (id=0x%x, %u frags)",
                         fs->key.ident, fs->frag_count);
                frag_stream_free_one(fs);
                g_stream_count--;
                cleaned++;
            } else {
                pp = &(*pp)->next;
            }
        }
    }

    return cleaned;
}

int ip_reasm_stream_count(void)
{
    return g_stream_count;
}

int ip_reasm_frag_count(void)
{
    return g_frag_total;
}
