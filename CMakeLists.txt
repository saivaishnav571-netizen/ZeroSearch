cmake_minimum_required(VERSION 3.15)

project(ZeroTrace)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(zerotrace

    src/main.cpp

    src/scanner.cpp

    src/detector.cpp

    src/entropy.cpp

    src/rule_engine.cpp

    src/redactor.cpp

    src/baseline.cpp

    src/sarif.cpp

    src/allowlist.cpp

)

target_include_directories(zerotrace PRIVATE

    ${CMAKE_CURRENT_SOURCE_DIR}/include

)