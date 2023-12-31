cmake_minimum_required(VERSION 3.10)

project(mps_sandbox)

set(CMAKE_CXX_STANDARD 11)
#set(CMAKE_BUILD_TYPE "Release")

find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(MultiPartySig REQUIRED)
find_package(GTest REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for *.pc file

set(SOURCES
        src/main.cpp
        src/Session.cpp
        src/Session.h
        src/Signer.cpp
        src/Signer.h
        src/message.h
        src/party_message_queue.h
        src/thread_safe_queue.h

)

add_executable(${PROJECT_NAME} ${SOURCES})

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