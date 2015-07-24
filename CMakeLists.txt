project(ext4-crypt)
cmake_minimum_required(VERSION 2.8)

include_directories(include)

set(SOURCES
    src/keys.c
    src/container.c
    src/ext4-crypt.c
)

add_executable(${CMAKE_PROJECT_NAME}
    ${SOURCES}
)

set(CMAKE_C_COMPILER "clang")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -std=gnu11")
target_link_libraries(${CMAKE_PROJECT_NAME} keyutils scrypt)
