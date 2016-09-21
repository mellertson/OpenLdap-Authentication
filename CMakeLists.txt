cmake_minimum_required(VERSION 3.5)
project(ldap_authenticate)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES main.cpp)
add_executable(ldap_authenticate ${SOURCE_FILES})

# **********************************************
# Link additional libaries
# **********************************************
target_link_libraries(ldap_authenticate ldap)