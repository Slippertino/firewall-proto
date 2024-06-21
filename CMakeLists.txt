cmake_minimum_required(VERSION 3.25)

project(firewall-proto C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(FIREWALL_SOURCES_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(FIREWALL_INCLUDE_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(FIREWALL_TESTS_DIR ${CMAKE_CURRENT_LIST_DIR}/tests)

set(FIREWALL_BUILD_TESTS ON)

file(GLOB_RECURSE FIREWALL_SOURCES ${FIREWALL_SOURCES_DIR}/*.c)
file(COPY ${CMAKE_CURRENT_LIST_DIR}/data DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

add_executable(firewall firewall.c)
target_sources(firewall PRIVATE ${FIREWALL_SOURCES})
target_include_directories(firewall PRIVATE ${FIREWALL_INCLUDE_DIR})

add_executable(generator generator.c)
target_sources(generator PRIVATE ${FIREWALL_SOURCES})
target_include_directories(generator PRIVATE ${FIREWALL_INCLUDE_DIR})

if (FIREWALL_BUILD_TESTS)
    add_subdirectory(${FIREWALL_TESTS_DIR})
endif(FIREWALL_BUILD_TESTS)