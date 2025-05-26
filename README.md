# BDT-FHE

A homomorphic encryption application built on the OpenFHE library.

## Overview

This project implements fully homomorphic encryption (FHE) using the OpenFHE library. The application is containerized with Docker for ease of deployment and consistent environment setup.

## Prerequisites

- Git
- Docker and Docker Compose


## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/Nima76/bdt-fhe.git
cd bdt-fhe
```

### 2. Create Docker network

```bash
docker network create soteria_network
```

### 3. Build and start containers

```bash
docker compose up --build -d
```

## Running Tests

Execute the following command to run the FHE encryption, processing, and decryption pipeline:

```bash
clear && \
docker exec fhe-enc sh -c "rm -rf /bdt/build/results/* /bdt/build/private_data/* /bdt/build/cryptocontext/*" && \
docker exec fhe-main sh -c "rm -rf /bdt/build/results/*" && \
echo "Cleaning volumes done!" && \
echo "============ Results ===============" && \
docker exec fhe-enc ls /bdt/build/results/ /bdt/build/private_data/ /bdt/build/cryptocontext/ && \
echo "=============================" && \
echo "Running FHE encryption..." && \
echo "=============================" && \
docker exec fhe-enc ./fhe-enc --security 256 --depth 8 --modulus 786433 && \
echo "Running FHE main..." && \
echo "=============================" && \
docker exec fhe-main ./fhe-main && \
echo "Running FHE decryption..." && \
echo "=============================" && \
docker exec fhe-dec ./fhe-dec
```

### Test Procedure Explained

The test command performs the following steps:

1. Clears the terminal view for a clean output of new test results
2. Removes previous test content from all container volumes to prepare for a fresh test run
3. Lists the contents of directories to confirm they're empty and ready for testing
4. Runs the encryption container (`fhe-enc`) with configurable parameters:
   - `--security 256`: Sets the security level
   - `--depth 8`: Sets the multiplicative depth
   - `--modulus 786433`: Sets the plaintext modulus

   Users can modify these parameters to encrypt datasets with different security levels and performance characteristics.

5. The encryption process generates output in Docker volumes:
   - Encrypted data is stored in the `encrypted_data` volume (accessible to `fhe-main`)
   - Private keys are stored in the `private_key` volume (accessible to `fhe-dec`)
   - Cryptocontext is stored in the `cryptocontext` volume (accessible to `fhe-dec`)

6. Runs the main processing container (`fhe-main`) which:
   - Automatically reads the encrypted data from the `encrypted_data` volume
   - Performs homomorphic operations on the encrypted data
   - Stores results in the `analytics_results` volume (accessible to `fhe-dec`)

7. Runs the decryption container (`fhe-dec`) which:
   - Reads results from the `analytics_results` volume
   - Uses the private key and cryptocontext to decrypt the results
   - Outputs the decrypted results

This workflow eliminates the need to manually copy files between containers as all data transfer happens through the mounted volumes.

## Execution Time Results

Each component of the application is equipped with an internal timer that tracks the execution time of various operations. These timing results are automatically saved in CSV format for performance analysis.

The timing data can be found in each component's directory:
```
/component-directory/build/timing/
```

For example:
- Encryption timing: `/bdt/build/timing/` in the `fhe-enc` container
- Processing timing: `/bdt/build/timing/` in the `fhe-main` container
- Decryption timing: `/bdt/build/timing/` in the `fhe-dec` container

This timing information is valuable for:
- Benchmarking different parameter configurations
- Optimizing performance bottlenecks
- Comparing execution time across different hardware setups

## Architecture

The application is divided into multiple Docker containers, each responsible for a specific part of the FHE process:

- `fhe-enc`: Handles encryption
- `fhe-main`: Processes encrypted data
- `fhe-dec`: Performs decryption

## Container Setup

This application uses Docker containers that are built on top of a base OpenFHE image. The base image is defined in the "ubuntu with open fhe" directory.

### Important Note on Modifications

If you want to modify the application or enable GPU acceleration service:

1. First modify the "ubuntu with openfhe" directory
2. Then rebuild and replace this image in the other components

Alternatively, you can use the pre-built image:
```
nimafrj/2204openfheuniman
```

This image was previously built based on the repository [FHE-HA-Integration](https://github.com/JPBultel/FHE-HA-Integration).

## Why Docker?

The OpenFHE library compilation process is time-consuming. Using Docker allows us to:
- Build the OpenFHE library once
- Create a base image that all components can use
- Ensure consistent environments across development and deployment

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

Please see the LICENSE file for details.
