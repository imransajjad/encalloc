/**
 * @file test-double-free.c
 * 
 * @brief tests safety of encalloc with double free cases
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <encalloc.h>
#include <time.h>


ENCALLOC_DECLARE_RESOURCES(my_pool, 100);

int main() {
    printf("Hello World\n");
    srand(0);   // Seed a random number with a known value for testing

    uint8_t key[ENCALLOC_KEY_SIZE] = {};

    ENCALLOC_INIT(my_pool, key);


    uint8_t *buf = encalloc(64);
    printf("buf alloc result: %p\n", buf);

    memcpy(buf, "This is a string", 17);
    printf("buf value %s\n", buf);

    uint8_t *buf2 = encalloc(64);
    printf("buf2 alloc result: %p\n", buf2);

    if (buf2) {
        memcpy(buf2, "This is a different string", 27);
        printf("buf2 value %s\n", buf2);
    }

    encfree(buf2);
    encfree(buf2);

    encfree(buf);
    encfree(buf);
    encfree((void*)10);

    uint8_t *buf3 = encalloc(64);
    printf("buf3 alloc result: %p\n", buf3);

    if (buf3) {
        memcpy(buf3, "This is a different string", 27);
        printf("buf3 value %s\n", buf3);
    }

    encfree(buf3);
    encfree(buf3);

    return 0;
}