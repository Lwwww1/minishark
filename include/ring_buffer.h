#ifndef RING_BUFFER_H
#define RING_BUFFER_H

/*
 * ring_buffer.h — 环形缓冲区 / 线程安全队列
 *
 * 用于抓包线程（生产者）与解析线程（消费者）之间传递数据包。
 * 基于 pthread 互斥锁 + 条件变量实现阻塞式 push/pop。
 *
 * 用法：
 *   rb = rb_init(1024);
 *   // 生产者线程
 *   rb_push(rb, &header, packet);
 *   // 消费者线程
 *   rb_pop(rb, &header, buf, &len);
 *   rb_destroy(rb);
 */

#include <pcap.h>
#include <pthread.h>
#include <stdint.h>

/* 单个槽位 */
struct rb_slot {
    struct pcap_pkthdr header;       /* 时间戳 + 长度 */
    uint8_t           *data;         /* 数据（已分配 MAX_PKT_SIZE 字节） */
    uint32_t           data_len;     /* 实际数据长度 */
};

/* 环形缓冲区 */
typedef struct ring_buffer_t {
    struct rb_slot *slots;           /* 槽位数组 */
    int             capacity;        /* 总槽位数 */
    int             head;            /* 消费者读取位置 */
    int             tail;            /* 生产者写入位置 */
    int             count;           /* 当前元素数 */
    pthread_mutex_t lock;            /* 互斥锁 */
    pthread_cond_t  not_empty;       /* 非空条件 */
    pthread_cond_t  not_full;        /* 非满条件 */
} ring_buffer_t;

/* 初始化，capacity 为最大包数，建议 1024~4096 */
ring_buffer_t *rb_init(int capacity);

/* 销毁并释放所有内存 */
void rb_destroy(ring_buffer_t *rb);

/* 生产者：放入一个包（若满则阻塞等待） */
void rb_push(ring_buffer_t *rb, const struct pcap_pkthdr *header,
             const u_char *packet);

/* 消费者：取出一个包（若空则阻塞等待） */
/* packet 缓冲区至少 MAX_PKT_SIZE 字节 */
void rb_pop(ring_buffer_t *rb, struct pcap_pkthdr *header,
            uint8_t *packet, uint32_t *len);

/* 带超时的 pop：timeout_ms 毫秒内无数据返回 0，拿到数据返回 1 */
int rb_pop_timeout(ring_buffer_t *rb, struct pcap_pkthdr *header,
                   uint8_t *packet, uint32_t *len, int timeout_ms);

/* 返回当前缓冲区中的元素个数（近似值） */
int rb_count(ring_buffer_t *rb);

#endif /* RING_BUFFER_H */
