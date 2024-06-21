cmake_minimum_required(VERSION 3.25)

project(firewall-tests C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)

file(
    COPY ${CMAKE_CURRENT_SOURCE_DIR}/run_all
    DESTINATION ${CMAKE_CURRENT_BINARY_DIR}
)

macro(test TEST_NAME)
    set(TEST test_${TEST_NAME})
    add_executable(${TEST} ${TEST}.c)
    target_sources(${TEST} PRIVATE ${FIREWALL_SOURCES})
    target_include_directories(${TEST} PRIVATE ${FIREWALL_INCLUDE_DIR} ${CMAKE_CURRENT_LIST_DIR})
    target_compile_definitions(${TEST} PRIVATE DISABLE_LOGGING)
    add_test(NAME ${TEST} COMMAND ${TEST})
endmacro()

test(utils)
test(net)
test(ep)
test(session)
test(rule)
test(checker)