# encalloc

```malloc``` and ```free``` equivalents that are secure against double free and possibly use after free.

Every call to ```encalloc``` calculates a simple hash and stores it in the metadata of the allocated chunk. Then upon a call to ```encfree```, the same hash is validated before actually freeing the buffer. Upon successful freeing, the stored hash is cleared so that calling free again will not pass the validation check.

The hashing function here is currently not cryptographically secure. It is a simple proof of concept at this point.

## Usage

Including as a cmake subdirectory is supported. In your project's ```CMakeLists.txt```, assuming this repo is at ```./external/encalloc```,

```cmake
set(CONFIG_ENCALLOC_ENABLE_ASSERTS ON)

add_subdirectory(external/encalloc)
target_link_libraries(your_app PRIVATE encalloc)

```

In addition to regular cmake options, there are
```cmake
CONFIG_ENCALLOC_SIMPLE # Use simpler encalloc implementation
CONFIG_ENCALLOC_ENABLE_ASSERTS # Enable custom prints and asserts
CONFIG_ENCALLOC_BUILD_TESTS # Build Tests
```

```find_package(encalloc)``` will be supported in the future.

## Building Tests

Build the project on its own and some tests will be built and put in the build directory

## A Simple Example Program

```c
#include <stdio.h>
#include <encalloc.h>
#include <time.h>
#include <stdlib.h>

// declare a memory pool of size 1000 and an "id"
ENCALLOC_DECLARE_RESOURCES(this_pool, 1000);

int main(void) {
    uint8_t key[ENCALLOC_KEY_SIZE];
    
    // initialize the pool with the key
    ENCALLOC_INIT(this_pool, key);
    // // seed the random number generator if desired
    // srand(time(NULL));

    uint8_t* buf = encalloc(40); // malloc equivalent

    if (NULL != buf) {
        snprintf(buf, 40, "This is a string");
        printf("%s\n", buf);
        encfree(buf); // free the buffer
        encfree(buf); // should be safe
    }

    return 0;
}
```
