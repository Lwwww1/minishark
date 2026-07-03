/*
 * ring_buffer.c — 环形缓冲区实现
 *
 * 线程安全的生产者-消费者队列。
 * push 在缓冲区满时阻塞等待，pop 在空时阻塞等待。
 */

#include "common.h"
#include "ring_buffer.h"

ring_buffer_t *rb_init(int capacity)
{
    if (capacity <= 0) {
        LOG_ERROR("rb_init: invalid capacity %d", capacity);
        return NULL;
    }

    ring_buffer_t *rb = calloc(1, sizeof(ring_buffer_t));
    if (rb == NULL) {
        LOG_ERROR("rb_init: out of memory");
        return NULL;
    }

    rb->slots = calloc((size_t)capacity, sizeof(struct rb_slot));
    if (rb->slots == NULL) {
        LOG_ERROR("rb_init: out of memory (slots)");
        free(rb);
        return NULL;
    }

    /* 预分配所有槽位的数据缓冲区，避免热路径上 malloc */
    for (int i = 0; i < capacity; i++) {
        rb->slots[i].data = malloc(MAX_PKT_SIZE);
        if (rb->slots[i].data == NULL) {
            LOG_ERROR("rb_init: out of memory (slot %d)", i);
            /* 清理已分配的 */
            for (int j = 0; j < i; j++)
                free(rb->slots[j].data);
            free(rb->slots);
            free(rb);
            return NULL;
        }
    }

    rb->capacity = capacity;
    rb->head     = 0;
    rb->tail     = 0;
    rb->count    = 0;

    pthread_mutex_init(&rb->lock, NULL);
    pthread_cond_init(&rb->not_empty, NULL);
    pthread_cond_init(&rb->not_full, NULL);

    LOG_INFO("ring buffer initialized: capacity=%d", capacity);
    return rb;
}

void rb_destroy(ring_buffer_t *rb)
{
    if (rb == NULL) return;

    for (int i = 0; i < rb->capacity; i++)
        free(rb->slots[i].data);
    free(rb->slots);

    pthread_mutex_destroy(&rb->lock);
    pthread_cond_destroy(&rb->not_empty);
    pthread_cond_destroy(&rb->not_full);

    free(rb);
    LOG_INFO("ring buffer destroyed");
}

void rb_push(ring_buffer_t *rb, const struct pcap_pkthdr *header,
             const u_char *packet)
{
    if (rb == NULL || header == NULL || packet == NULL) return;

    pthread_mutex_lock(&rb->lock);

    /* 缓冲区满 → 等待消费者腾出空间 */
    while (rb->count >= rb->capacity) {
        pthread_cond_wait(&rb->not_full, &rb->lock);
    }

    struct rb_slot *slot = &rb->slots[rb->tail];

    /* 拷贝包数据 */
    slot->header   = *header;
    slot->data_len = header->caplen;
    if (slot->data_len > MAX_PKT_SIZE)
        slot->data_len = MAX_PKT_SIZE;
    memcpy(slot->data, packet, slot->data_len);

    rb->tail = (rb->tail + 1) % rb->capacity;
    rb->count++;

    pthread_cond_signal(&rb->not_empty);
    pthread_mutex_unlock(&rb->lock);
}

void rb_pop(ring_buffer_t *rb, struct pcap_pkthdr *header,
            uint8_t *packet, uint32_t *len)
{
    if (rb == NULL || header == NULL || packet == NULL || len == NULL) return;

    pthread_mutex_lock(&rb->lock);

    /* 缓冲区空 → 等待生产者放入数据 */
    while (rb->count <= 0) {
        pthread_cond_wait(&rb->not_empty, &rb->lock);
    }

    struct rb_slot *slot = &rb->slots[rb->head];

    /* 拷贝包数据到调用方缓冲区 */
    *header = slot->header;
    *len    = slot->data_len;
    if (*len > MAX_PKT_SIZE)
        *len = MAX_PKT_SIZE;
    memcpy(packet, slot->data, *len);

    rb->head = (rb->head + 1) % rb->capacity;
    rb->count--;

    pthread_cond_signal(&rb->not_full);
    pthread_mutex_unlock(&rb->lock);
}

int rb_pop_timeout(ring_buffer_t *rb, struct pcap_pkthdr *header,
                   uint8_t *packet, uint32_t *len, int timeout_ms)
{
    if (rb == NULL || header == NULL || packet == NULL || len == NULL) return -1;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec  += timeout_ms / 1000;
    ts.tv_nsec += (timeout_ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec  += 1;
        ts.tv_nsec -= 1000000000L;
    }

    pthread_mutex_lock(&rb->lock);

    while (rb->count <= 0) {
        int rc = pthread_cond_timedwait(&rb->not_empty, &rb->lock, &ts);
        if (rc == ETIMEDOUT) {
            pthread_mutex_unlock(&rb->lock);
            return 0;
        }
    }

    struct rb_slot *slot = &rb->slots[rb->head];
    *header = slot->header;
    *len    = slot->data_len;
    if (*len > MAX_PKT_SIZE) *len = MAX_PKT_SIZE;
    memcpy(packet, slot->data, *len);

    rb->head = (rb->head + 1) % rb->capacity;
    rb->count--;

    pthread_cond_signal(&rb->not_full);
    pthread_mutex_unlock(&rb->lock);
    return 1;
}

int rb_count(ring_buffer_t *rb)
{
    if (rb == NULL) return 0;
    pthread_mutex_lock(&rb->lock);
    int c = rb->count;
    pthread_mutex_unlock(&rb->lock);
    return c;
}
