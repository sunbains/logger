cmake_minimum_required(VERSION 3.14)
project(logger CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Create header-only library target (INTERFACE)
add_library(${PROJECT_NAME} INTERFACE)

target_include_directories(${PROGJECT_NAME} INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(${PROJECT_NAME} INTERFACE )
