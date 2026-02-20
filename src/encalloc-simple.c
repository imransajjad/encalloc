/**
 * @file encalloc-simple.c
 * 
 * @brief A simple version of encrypted malloc and free operations
 * Uses malloc internally. Not safe but good proof of concept
 */

#include <stdlib.h>
#include <stdbool.h>
#include <assert-print.h>
#include <encalloc.h>


static const uint8_t *m_key;

struct enc_header_s {
    void *buf_start;
    uint32_t init;
    uint32_t hash;
};

static uint32_t get_hash(const struct enc_header_s *header) {
    uint32_t hash = (uint64_t) (header->buf_start);

    uint32_t *key = (uint32_t*)m_key;
    size_t key_words = ENCALLOC_KEY_SIZE/sizeof(uint32_t);

    hash ^= header->init + 1;

    for (size_t i = 0; i < key_words; i++) {
        hash ^= key[i] + 1;
    }
    return hash;
}

static void print_header_info(const struct enc_header_s *h) {
    (void)h;
    DEBUG_PRINTF("header at: 0x%p\n", (void*)h);
    DEBUG_PRINTF("\tbuffer_start:0x%p\n", h->buf_start);
    DEBUG_PRINTF("\tinit:        0x%08x\n", h->init);
    DEBUG_PRINTF("\thash:        0x%08x\n", h->hash);
    DEBUG_PRINTF("\tcalc_hash:   0x%08x\n", get_hash(h));
}

// public functions

void __encalloc_assign_init(const uint8_t *secure_key, void *pool, size_t pool_size) {
    m_key = secure_key;
    (void)pool;
    (void)pool_size;
}

void *encalloc(size_t nbytes) {
    uint8_t* buf =  malloc(nbytes + sizeof(struct enc_header_s));

    struct enc_header_s header = {
        .buf_start = buf,
        .init = (rand() << 16) + rand(),
    };
    header.hash = get_hash(&header);
    memcpy(buf, &header, sizeof(struct enc_header_s));
    return buf + sizeof(struct enc_header_s);
}

void encfree(void *mem) {
    if (NULL == mem) {
        return;
    }
    if (sizeof(struct enc_header_s) > (size_t)mem) {
        return;
    }
    uint8_t* buf = (uint8_t*)mem - sizeof(struct enc_header_s);
    struct enc_header_s header;
    memcpy(&header, buf, sizeof(struct enc_header_s));

    print_header_info(&header);

    if (header.hash == get_hash(&header)) {
        header.init = 0;
        header.hash = 0;
        memcpy(buf, &header, sizeof(struct enc_header_s));
        free(buf);
        DEBUG_PRINTF("Called encfree on valid buffer %p\n", mem);
    } else {
        DEBUG_PRINTF("Called encfree on invalid buffer %p, skipping\n", mem);
    }
}
