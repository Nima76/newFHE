#FROM ubuntu:20.04

FROM nimafrj/2004openfhe:1.0.3

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

WORKDIR /app
# Copy the source code
COPY FHE-enc-modified.cpp /app/FHE-enc.cpp


RUN cp /usr/src/app/openfhe-development/CMakeLists.User.txt ./CMakeLists.txt
RUN echo "add_executable(fhe-enc FHE-enc.cpp)" >> CMakeLists.txt

RUN mkdir /app/build /app/results /app/data /app/private_data
WORKDIR /app/build
RUN cmake ..
RUN make
RUN mv fhe-enc ../
WORKDIR /app
RUN rm -rf ./build CMakeLists.txt FHE-enc.cpp

# Compile the application
# RUN g++ -o FHE-enc FHE-enc.cpp -fopenmp -std=c++17 -lOPENFHEpke -lOPENFHEcore -pthread

# Create directories
RUN mkdir -p data results private_data

# Set permissions
RUN chmod +x fhe-enc

# Command to run
CMD ["bash", "-l"] 