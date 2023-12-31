cmake_minimum_required(VERSION 3.26)
project(test)

set(CMAKE_CXX_STANDARD 11)
#set(CMAKE_BUILD_TYPE "Release")

find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for *.pc file
#set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
find_package(MultiPartySig REQUIRED)
find_package(GTest REQUIRED)
set(MAIN_SOURCES
    main.cpp
        message.h
        party_message_queue.h
        thread_safe_queue.h
)
#set(MultiPartySig_INCLUDE_DIR ~/Projects/multi-party-sig-cpp/)

add_executable(${PROJECT_NAME} ${MAIN_SOURCES})
target_include_directories(${PROJECT_NAME} PUBLIC
        ${MultiPartySig_INCLUDE_DIRS}
        ${PROTOBUF_INCLUDE_DIRS}
)

target_link_libraries(${PROJECT_NAME} PUBLIC
        MultiPartySig
        OpenSSL::Crypto
        ${PROTOBUF_LINK_LIBRARIES}
        pthread
        GTest::gtest_main
)
project(cmp_creation)
set(CMP_SOURCES
        cmp_creation.cpp
        message.h
        party_message_queue.h
        thread_safe_queue.h
)
add_executable(${PROJECT_NAME} ${CMP_SOURCES})
target_include_directories(${PROJECT_NAME} PUBLIC
        ${MultiPartySig_INCLUDE_DIRS}
        ${PROTOBUF_INCLUDE_DIRS}
)

target_link_libraries(${PROJECT_NAME} PUBLIC
        MultiPartySig
        OpenSSL::Crypto
        ${PROTOBUF_LINK_LIBRARIES}
        pthread
        GTest::gtest_main
)

add_subdirectory(sandbox)

