#FROM ubuntu:20.04

FROM nimafrj/2204openfhe:1.0.3

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

# RUN git clone https://github.com/openfheorg/openfhe-development.git 

# WORKDIR /usr/src/app/openfhe-development

# RUN git checkout v1.0.3 && \
#     git submodule init && \
#     git submodule update && \
#     mkdir build && \
#     cd build && \
#     cmake .. -DBUILD_BENCHMARKS=OFF && \
#     make && \
#     make install && \
#     ldconfig

WORKDIR /bdt
# Copy the source code
COPY . .


RUN cp /usr/src/app/openfhe-development/CMakeLists.User.txt ./CMakeLists.txt
RUN echo "add_executable(fhe-enc fhe-enc.cpp)" >> CMakeLists.txt

RUN mkdir -p /bdt/build /bdt/build/results /bdt/build/data /bdt/build/private_data /bdt/build/timing /bdt/build/cryptocontext
WORKDIR /bdt/build
RUN cmake ..
RUN make

# Compile the application
# RUN g++ -o FHE-enc FHE-enc.cpp -fopenmp -std=c++17 -lOPENFHEpke -lOPENFHEcore -pthread

# Create directories

# Set permissions
RUN chmod +x fhe-enc

# Command to run
CMD ["bash", "-l"] 