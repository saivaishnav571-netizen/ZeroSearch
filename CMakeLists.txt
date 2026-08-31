cmake_minimum_required(VERSION 3.16)

project(ZeroTrace
    VERSION 1.0
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(zerotrace
    src/main.cpp
    src/scanner.cpp
)

target_include_directories(zerotrace
    PRIVATE
    include
)