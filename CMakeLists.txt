set(CMAKE_BUILD_TYPE release)
cmake_minimum_required(VERSION 3.4)

find_package(LibArchive REQUIRED)
add_executable(arc-convert src/arc-convert.cpp)
set_target_properties(arc-convert PROPERTIES CXX_STANDARD 11)
target_include_directories(arc-convert PUBLIC ${LibArchive_INCLUDE_DIRS})
target_link_libraries(arc-convert PUBLIC ${LibArchive_LIBRARIES})
