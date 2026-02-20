/**
 * @file encalloc.h
 * 
 * @brief this module defines a cryptographically secure way to allocate
 *  memory on a heap section while having the additional advantage that
 *  calling free twice on cryptographically secure memory will not have
 *  any adverse effects
 */

#ifndef ENCALLOC_H_
#define ENCALLOC_H_

#include <stdint.h>
#include <string.h>

#define ENCALLOC_KEY_SIZE 32

// if data needs to be encrypted upon load/store, consider putting these in their
// own section with __attribute__((section("."#ID)))
#define ENCALLOC_DECLARE_RESOURCES(ID, CAPACITY)\
    static uint8_t __encalloc_##ID##_key[ENCALLOC_KEY_SIZE];   \
    static uint8_t __encalloc_##ID##_bytes[(CAPACITY)];  \

// When calling this function it is a good idea to seed the random number
// generator using srand(time(NULL))
#define ENCALLOC_INIT(ID, KEY)\
    memcpy(__encalloc_##ID##_key, KEY, ENCALLOC_KEY_SIZE);\
    __encalloc_assign_init(__encalloc_##ID##_key, __encalloc_##ID##_bytes, sizeof(__encalloc_##ID##_bytes));

/**
 * @brief initialize a pool to allocate a cryptographically secure chunk of bytes
 * 
 * @param secure_key the key to use with this operation
 * @param pool the memory buffer to use
 *  if pool is NULL, malloc will be used under the hood
 * @param pool_size the size of the pool
 */
void __encalloc_assign_init(const uint8_t *secure_key, void *pool, size_t pool_size);

/**
 * @brief allocate a cryptographically secure chunk of bytes
 * 
 * @param nbytes the number of bytes to allocate
 * @return pointer to the allocated memory
 */
void *encalloc(size_t nbytes);

/**
 * @brief free a memory previously allocated by encalloc
 * 
 * @param mem pointer to the allocated memory
 */
void encfree(void *mem);

#endif //ENCALLOC_H_
