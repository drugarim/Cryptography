cmake_minimum_required(VERSION 3.25)
project(botan-example)

set(CMAKE_CXX_STANDARD 17)

file(GLOB project_sources CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/*.cpp" "${CMAKE_SOURCE_DIR}/include/*.h")
#add_executable(botan-example src/main.cpp)
add_executable(botan-example ${project_sources} src/main.cpp
        src/global.cpp)
target_include_directories(botan-example PRIVATE include/ lib/include)
#target_link_directories(botan-example lib/bin/)
target_link_libraries(botan-example ${CMAKE_SOURCE_DIR}/lib/bin/libbotan-2.so)
