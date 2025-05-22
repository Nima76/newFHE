FROM ubuntu:20.04

WORKDIR /usr/src/app
# Install dependencies
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    wget \
    unzip \
    python3 \
    python3-pip \
    libgmp-dev \
    libntl-dev \
    doxygen \
    graphviz \
    && rm -rf /var/lib/apt/lists/*

# Working directory

# Clone and build OpenFHE

RUN git clone https://github.com/openfheorg/openfhe-development.git 

WORKDIR /usr/src/app/openfhe-development

RUN git checkout v1.0.3 && \
    git submodule init && \
    git submodule update && \
    mkdir build && \
    cd build && \
    cmake .. -DBUILD_BENCHMARKS=OFF && \
    make && \
    make install && \
    ldconfig

CMD ["bash", "-l"] 