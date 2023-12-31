FROM ubuntu:latest
LABEL authors="dinozood"

RUN mkdir /root/project
WORKDIR /root/project
COPY * ./

RUN apt-get update \
    && apt-get install -y \
    git \
    make \
    cmake \
    gcc \
    g++ \
    pkg-config \
    openssl \
    libssl-dev \
    libgtest-dev \
    autoconf automake libtool curl make g++ unzip \
    sed \
    && apt-get autoclean

RUN git clone https://github.com/protocolbuffers/protobuf.git \
&& cd protobuf \
&& git checkout v3.14.0 \
&& git submodule update --init --recursive \
&& ./autogen.sh \
&& ./configure \
&& make -j$(nproc) \
&& make check \
&& make install \
&& ldconfig # refresh shared library cache.

RUN git clone --recurse-submodules https://github.com/safeheron/safeheron-crypto-suites-cpp.git
RUN sed -i '10 i #include <cstring>' /root/project/safeheron-crypto-suites-cpp/src/crypto-suites/exception/located_exception.h
RUN cd safeheron-crypto-suites-cpp \
&& mkdir build && cd build \
&& cmake ../  -DENABLE_TESTS=ON \
&& make \
&& make test \
&& make install

RUN git clone https://github.com/safeheron/multi-party-sig-cpp.git
RUN cd multi-party-sig-cpp \
&& git submodule update --recursive --init \
&& mkdir build && cd build \
&& cmake ..  -DENABLE_TESTS=ON \
&& make \
&& make test \
&& make install