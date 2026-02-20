/**
 * @file assert-print.h
 * 
 * @brief some assert and print functions that can be enabled
 */

#ifndef ASSERT_H_
#define ASSERT_H_

#ifdef CONFIG_ENCALLOC_ENABLE_ASSERTS

#include <stdlib.h>
#include <stdio.h>

#define ASSERT(COND)\
    if (!(COND)) {\
        printf("Assert failed: " #COND " on %s::%s:%d\n", __FILE__, __func__, __LINE__);\
        abort();\
    }\

#define DEBUG_PRINTF(...) printf(__VA_ARGS__)

#else
#define ASSERT(COND)
#define DEBUG_PRINTF(...)

#endif //CONFIG_ENCALLOC_ENABLE_ASSERTS

#endif //ASSERT_H_
