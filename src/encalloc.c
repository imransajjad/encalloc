
/**
 * @file encalloc.c
 * 
 * @brief an attempt to do cryptographically secure malloc and free operations
 * this implementation will probably have malloc/free bugs
 */

#include <stdlib.h>
#include <stdbool.h>
#include <assert-print.h>
#include <encalloc.h>

// typedefs and statics

struct pool_obj_s {
    uint8_t *boundary_start;
    uint8_t *boundary_end;
    uint32_t init_random;
    uint32_t boundary_hash;
} __packed;


struct module_data_s {
    uint32_t key;
    uint8_t *pool;
    size_t capacity;

    struct pool_obj_s *head;
    // a cicrular singly linked list, this is where we'll start the search from
};

static struct module_data_s m_data;

// Common utility functions

static uint32_t calc_hash(const struct pool_obj_s *obj) {
    uint32_t hash = (uint32_t)(uintptr_t) (obj->boundary_start);
    hash ^= obj->init_random;
    hash ^= m_data.key;

    hash *= 0x9e3779b1;   // golden ratio
    hash ^= hash >> 16;
    return hash;
}

inline static bool has_data(struct pool_obj_s *obj) {
    return (obj->init_random != 0) && (calc_hash(obj) == obj->boundary_hash);
}

static bool is_large_enough(struct pool_obj_s *obj, size_t nbytes) {
    // return ((obj->boundary_end - obj->boundary_start - sizeof(struct pool_obj_s)) >= nbytes);
    return (obj->boundary_end >= (obj->boundary_start + sizeof(struct pool_obj_s) + nbytes));
}

inline static bool inbounds(void *mem) {
    return ((m_data.pool <= (uint8_t*)mem) && ((uint8_t*)mem < m_data.pool + m_data.capacity));
}


static inline void reserve_block(struct pool_obj_s *obj, size_t nbytes) {
    obj->boundary_start = (uint8_t*)obj;
    obj->boundary_end = obj->boundary_start + nbytes + sizeof(struct pool_obj_s);
    obj->init_random = (rand() << 16) + rand();
    obj->boundary_hash = calc_hash(obj);
}

static inline void init_block(struct pool_obj_s *obj, uint8_t *end_mem) {
    obj->boundary_start = (uint8_t*)obj;
    obj->boundary_end = end_mem;
    obj->init_random = 0;
}

static void *split_block(struct pool_obj_s *obj, size_t nbytes) {
    if (!is_large_enough(obj, nbytes)) {
        return NULL;
    }
    uint8_t *end_mem = obj->boundary_end;
    reserve_block(obj, nbytes);
    struct pool_obj_s *split = (struct pool_obj_s *) obj->boundary_end;
    init_block(split, end_mem);
    return split;
}

static void *get_next_empty(struct pool_obj_s *obj, size_t nbytes) {
    const struct pool_obj_s *seen = NULL;
    while (has_data(obj) || !is_large_enough(obj, nbytes)) {
        if (obj == seen) {
            return NULL;
        }
        if (NULL == seen) {
            seen = obj;
        }
        obj = (struct pool_obj_s*) obj->boundary_end;
        if (!inbounds(obj)) {
            return NULL;
        }
    }
    return obj;
}

static void print_header_info(const struct pool_obj_s *obj) {
    (void)obj;
    DEBUG_PRINTF("header at: 0x%p\n", (void*)obj);
    DEBUG_PRINTF("\tboundary_start:0x%p\n", obj->boundary_start);
    DEBUG_PRINTF("\tboundary_end:  0x%p\n", obj->boundary_end);
    DEBUG_PRINTF("\tinit_random:   0x%08x\n", obj->init_random);
    DEBUG_PRINTF("\tboundary_hash: 0x%08x\n", obj->boundary_hash);
    DEBUG_PRINTF("\tcalc_hash:     0x%08x\n", calc_hash(obj));
}

// Public functions

void __encalloc_assign_init(const uint8_t *secure_key, void *pool, size_t pool_size) {
    uint32_t *key = (uint32_t*)secure_key;

    m_data.key = 0;
    for (size_t i = 0 ; i < ENCALLOC_KEY_SIZE/sizeof(uint32_t); i++) {
        m_data.key ^= key[i];
    }

    if (NULL == pool) {
        // in this case, we will just use malloc once to get pool_size on the heap
        m_data.pool = malloc(pool_size);
        ASSERT(m_data.pool != NULL);
        m_data.capacity = pool_size;
    } else {
        m_data.pool = pool;
        m_data.capacity = pool_size;
    }

    init_block( (struct pool_obj_s*) m_data.pool, (uint8_t*)m_data.pool + m_data.capacity);
    m_data.head = (struct pool_obj_s *)m_data.pool;
}



void *encalloc(size_t nbytes) {

    struct pool_obj_s *cur_mem = get_next_empty(m_data.head, nbytes);
    if (NULL == cur_mem ) {
        cur_mem = get_next_empty( (struct pool_obj_s *)m_data.pool, nbytes);
        if (NULL == cur_mem ) {
            return NULL;
        }
        m_data.head = (struct pool_obj_s *)m_data.pool;
    }
    // allocate the bytes here and adjust accordintly
    void *new_mem = split_block(cur_mem, nbytes);
    if (NULL == new_mem) {
        return NULL;
    }
    m_data.head = new_mem;
    return cur_mem->boundary_start + sizeof(struct pool_obj_s);
}

void encfree(void *mem) {
    if (mem == NULL) {
        return;
    }
    if (sizeof(struct pool_obj_s) > (size_t)mem) {
        return;
    }
    ASSERT(inbounds(mem));
    ASSERT((uint8_t*)mem >= m_data.pool + sizeof(struct pool_obj_s));

    struct pool_obj_s* obj = (struct pool_obj_s*)  ((uint8_t*)mem - sizeof(struct pool_obj_s));
    
    if (has_data(obj)) {
        DEBUG_PRINTF("encfreeeing valid buffer at 0x%p\n", mem);
        print_header_info(obj);

        struct pool_obj_s* search = (struct pool_obj_s*) obj->boundary_end;

        while (!has_data(search) && inbounds(search)) {
            search = (struct pool_obj_s*) search->boundary_end;
        }
        init_block(obj, (uint8_t*) search);
    } else {
        DEBUG_PRINTF("encfree called on invalid valid buffer at 0x%p, skipping\n", mem);
        print_header_info(obj);
    }
}
