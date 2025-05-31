cmake_minimum_required(VERSION 3.31)
project(nnscproxy)

set(CMAKE_CXX_STANDARD 23)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(cpprestsdk REQUIRED)

add_subdirectory(webserver)

add_executable(nnscproxy main.cpp)

target_link_libraries(nnscproxy PRIVATE webserver)
target_link_libraries(nnscproxy PRIVATE cpprestsdk::cpprest -lcrypto)

install(TARGETS nnscproxy DESTINATION bin)
