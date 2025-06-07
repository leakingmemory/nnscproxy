cmake_minimum_required(VERSION 3.31)
project(nnscproxy LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if (${CMAKE_SYSTEM_NAME} STREQUAL "FreeBSD")
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    set(CMAKE_CXX_EXTENSIONS OFF)
    add_compile_options("-I/usr/include")
    add_compile_options("-I/usr/local/include")
    add_compile_options("-I/usr/local/include/PCSC")
    add_compile_options("-DFREEBSD")
    add_link_options("-L/usr/local/lib")
endif()

find_package(cpprestsdk REQUIRED)

add_subdirectory(webserver)

add_executable(nnscproxy main.cpp)

target_link_libraries(nnscproxy PRIVATE webserver)
target_link_libraries(nnscproxy PRIVATE cpprestsdk::cpprest -lcrypto)

install(TARGETS nnscproxy DESTINATION bin)
