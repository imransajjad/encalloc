
cmake_minimum_required(VERSION 3.19)

project(enalloc-project LANGUAGES C)


option(CONFIG_ENCALLOC_SIMPLE "Use simple encalloc implementation" ON)
option(CONFIG_ENCALLOC_ENABLE_ASSERTS "Enable custom prints and asserts" OFF)

if (CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    option(CONFIG_ENCALLOC_BUILD_TESTS "Build Tests" ON)
else()
    option(CONFIG_ENCALLOC_BUILD_TESTS "Build Tests" OFF)
endif()

if (CONFIG_ENCALLOC_SIMPLE)
    set(ENCALLOC_SRC ${CMAKE_CURRENT_LIST_DIR}/src/encalloc-simple.c)
else()
    set(ENCALLOC_SRC ${CMAKE_CURRENT_LIST_DIR}/src/encalloc.c)
endif()


add_library(encalloc ${ENCALLOC_SRC})
target_include_directories(encalloc PUBLIC  ${CMAKE_CURRENT_LIST_DIR}/include)

target_compile_features(encalloc PUBLIC c_std_11)
target_compile_options(encalloc PRIVATE -Wall -Wextra -Wpedantic)

if (CONFIG_ENCALLOC_SIMPLE)
    target_compile_definitions(encalloc PUBLIC CONFIG_ENCALLOC_SIMPLE=1)
endif()

if (CONFIG_ENCALLOC_ENABLE_ASSERTS)
    target_compile_definitions(encalloc PUBLIC CONFIG_ENCALLOC_ENABLE_ASSERTS=1)
endif()


if (CONFIG_ENCALLOC_BUILD_TESTS)
    enable_testing()

    add_executable(test-double-free tests/test-double-free.c)
    target_link_libraries(test-double-free PRIVATE encalloc)

    add_test(NAME test-double-free COMMAND test-double-free)
endif()
