#!/usr/bin/env python3
# filepath: user_vm.py
import os
import time
import docker
import logging
import tarfile
import tempfile
import io

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def copy_between_containers1(source_container, source_path, target_container, 
                           target_path, target_speed_mbps=30.0, chunk_size=4096, 
                           operation_name="Transfer"):
    """
    Copy files from source container to target container with speed limiting
    
    Args:
        source_container: Name/ID of source container
        source_path: Path in source container to copy from
        target_container: Name/ID of target container
        target_path: Path in target container to copy to
        target_speed_mbps: Speed limit in Mbps
        chunk_size: Size of chunks to read/write
        operation_name: Name of the operation for timing logs
    """
    client = docker.from_env()
    
    # Get container objects
    try:
        src_container = client.containers.get(source_container)
        dst_container = client.containers.get(target_container)
    except docker.errors.NotFound as e:
        logger.error(f"Container not found: {e}")
        return False, 0
        
    logger.info(f"Copying from {source_container}:{source_path} to {target_container}:{target_path}")
    
    # Calculate delay for throttling
    target_speed_bps = target_speed_mbps * 1_000_000  # Mbps to bps
    delay_per_chunk = chunk_size * 8 / target_speed_bps  # Delay in seconds per chunk
    
    transfer_start = time.time()
    
    # Get file or directory from source container
    try:
        bits, stat = src_container.get_archive(source_path)
        
        # Create in-memory file from the archive stream
        file_obj = io.BytesIO()
        for chunk in bits:
            file_obj.write(chunk)
            time.sleep(delay_per_chunk)  # Simulate limited bandwidth
            
        file_obj.seek(0)
        
        # Extract to a temporary directory
        with tempfile.TemporaryDirectory() as tmp_dir:
            with tarfile.open(fileobj=file_obj) as tar:
                tar.extractall(path=tmp_dir)
            
            # Create a new tar archive for the destination
            tar_path = os.path.join(tmp_dir, "transfer.tar")
            with tarfile.open(tar_path, "w") as tar:
                base_dir = os.path.basename(os.path.normpath(source_path))
                src_path = os.path.join(tmp_dir, base_dir)
                
                # Handle both file and directory cases
                if os.path.isdir(src_path):
                    for root, dirs, files in os.walk(src_path):
                        for file in files:
                            full_path = os.path.join(root, file)
                            tar.add(full_path, arcname=os.path.relpath(full_path, tmp_dir))
                else:
                    tar.add(src_path, arcname=base_dir)
            
            # Put the archive in the target container
            with open(tar_path, 'rb') as f:
                dst_container.put_archive(os.path.dirname(target_path), f.read())
    
    except Exception as e:
        logger.error(f"Error during file transfer: {e}")
        return False, 0
        
    transfer_end = time.time()
    transfer_time = transfer_end - transfer_start
    logger.info(f"\033[1;31mTIMER: {operation_name} completed in: \033[1;33m{transfer_time:.6f} seconds")
    
    return True, transfer_time
def copy_between_containers(source_container, source_path, target_container, 
                           target_path, target_speed_mbps=30.0, chunk_size=4096, 
                           operation_name="Transfer", flatten_directory=False):
    """
    Copy files from source container to target container with speed limiting
    
    Args:
        source_container: Name/ID of source container
        source_path: Path in source container to copy from
        target_container: Name/ID of target container
        target_path: Path in target container to copy to
        target_speed_mbps: Speed limit in Mbps
        chunk_size: Size of chunks to read/write
        operation_name: Name of the operation for timing logs
        flatten_directory: If True, copy files directly to target without preserving source dir structure
    """
    client = docker.from_env()
    
    # Get container objects
    try:
        src_container = client.containers.get(source_container)
        dst_container = client.containers.get(target_container)
    except docker.errors.NotFound as e:
        logger.error(f"Container not found: {e}")
        return False, 0
        
    logger.info(f"Copying from {source_container}:{source_path} to {target_container}:{target_path}")
    
    # Calculate delay for throttling
    target_speed_bps = target_speed_mbps * 1_000_000  # Mbps to bps
    delay_per_chunk = chunk_size * 8 / target_speed_bps  # Delay in seconds per chunk
    
    transfer_start = time.time()
    
    # Get file or directory from source container
    try:
        bits, stat = src_container.get_archive(source_path)
        
        # Create in-memory file from the archive stream
        file_obj = io.BytesIO()
        for chunk in bits:
            file_obj.write(chunk)
            time.sleep(delay_per_chunk)  # Simulate limited bandwidth
            
        file_obj.seek(0)
        
        # Extract to a temporary directory
        with tempfile.TemporaryDirectory() as tmp_dir:
            with tarfile.open(fileobj=file_obj) as tar:
                tar.extractall(path=tmp_dir)
            
            # Create a new tar archive for the destination
            tar_path = os.path.join(tmp_dir, "transfer.tar")
            with tarfile.open(tar_path, "w") as tar:
                base_dir = os.path.basename(os.path.normpath(source_path))
                src_path = os.path.join(tmp_dir, base_dir)
                
                # Handle both file and directory cases
                if os.path.isdir(src_path) and flatten_directory:
                    # Just add files directly, without preserving directory structure
                    for root, dirs, files in os.walk(src_path):
                        for file in files:
                            full_path = os.path.join(root, file)
                            tar.add(full_path, arcname=os.path.basename(full_path))
                elif os.path.isdir(src_path):
                    # Preserve directory structure (original behavior)
                    for root, dirs, files in os.walk(src_path):
                        for file in files:
                            full_path = os.path.join(root, file)
                            tar.add(full_path, arcname=os.path.relpath(full_path, tmp_dir))
                else:
                    tar.add(src_path, arcname=base_dir)
            
            # Put the archive in the target container
            with open(tar_path, 'rb') as f:
                dst_container.put_archive(os.path.dirname(target_path), f.read())
    
    except Exception as e:
        logger.error(f"Error during file transfer: {e}")
        return False, 0
        
    transfer_end = time.time()
    transfer_time = transfer_end - transfer_start
    logger.info(f"\033[1;31mTIMER: {operation_name} completed in: \033[1;33m{transfer_time:.6f} seconds")
    
    return True, transfer_time

def copy_between_containers_bash(source_container, source_path, target_container, 
                               target_path, target_speed_mbps=30.0, 
                               operation_name="Transfer", flatten_directory=False):
    """
    Copy files from source container to target container with speed limiting using bash commands
    
    Args:
        source_container: Name/ID of source container
        source_path: Path in source container to copy from
        target_container: Name/ID of target container
        target_path: Path in target container to copy to
        target_speed_mbps: Speed limit in Mbps
        operation_name: Name of the operation for timing logs
        flatten_directory: If True, copy files directly to target without preserving source dir structure
    """
    import subprocess
    import shlex
    import os
    import time
    
    logger.info(f"Copying from {source_container}:{source_path} to {target_container}:{target_path}")
    
    # Convert target_speed_mbps to bytes per second
    target_speed_bps = target_speed_mbps * 1_000_000 / 8  # Mbps to Bytes/s
    chunk_size = 4096  # Use a reasonable chunk size
    delay_per_chunk = chunk_size / target_speed_bps  # Delay per chunk in seconds
    
    transfer_start = time.time()
    
    # Create temporary directory on host
    temp_dir = "./temp_dir"
    os.makedirs(temp_dir, exist_ok=True)
    
    try:
        # Step 1: Copy from source container to host temp dir
        if flatten_directory:
            # List all files in source directory
            cmd = f"docker exec {source_container} find {source_path} -type f"
            result = subprocess.run(shlex.split(cmd), capture_output=True, text=True)
            source_files = [f for f in result.stdout.strip().split('\n') if f]
            
            # Copy each file to temp directory with flattened structure
            for src_file in source_files:
                file_name = os.path.basename(src_file)
                temp_file = os.path.join(temp_dir, file_name)
                
                # Copy from container to host (without rate limiting)
                subprocess.run(["docker", "cp", f"{source_container}:{src_file}", temp_file])
                
                # Step 2 & 3: Copy from host to target container with rate limiting
                with open(temp_file, 'rb') as f:
                    file_chunks = []
                    while True:
                        chunk = f.read(chunk_size)
                        if not chunk:
                            break
                        file_chunks.append(chunk)
                        time.sleep(delay_per_chunk)  # Apply rate limiting
                
                # Ensure target directory exists
                target_dir = os.path.dirname(os.path.join(target_path, file_name))
                subprocess.run(["docker", "exec", target_container, "mkdir", "-p", target_dir])
                
                # Write to destination container
                dst_file = os.path.join(target_path, file_name)
                subprocess.run(["docker", "cp", temp_file, f"{target_container}:{dst_file}"])
        else:
            # For directory structure preservation, use tar
            tar_file = os.path.join(temp_dir, "transfer.tar")
            
            # Step 1: Create tar from source container and save to host
            cmd = f"docker exec {source_container} tar -cf - -C {os.path.dirname(source_path)} {os.path.basename(source_path)}"
            with subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE) as proc:
                with open(tar_file, 'wb') as f:
                    while True:
                        chunk = proc.stdout.read(chunk_size)
                        if not chunk:
                            break
                        f.write(chunk)
            
            # Step 2 & 3: Copy tar to target container with rate limiting
            with open(tar_file, 'rb') as f:
                file_size = os.path.getsize(tar_file)
                bytes_read = 0
                
                while bytes_read < file_size:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    bytes_read += len(chunk)
                    time.sleep(delay_per_chunk)  # Apply rate limiting
            
            # Ensure target directory exists
            subprocess.run(["docker", "exec", target_container, "mkdir", "-p", os.path.dirname(target_path)])
            
            # Copy tar to target container
            dst_tar = os.path.join(os.path.dirname(target_path), "transfer.tar")
            subprocess.run(["docker", "cp", tar_file, f"{target_container}:{dst_tar}"])
            
            # Extract tar in target container
            cmd = f"docker exec {target_container} tar -xf {dst_tar} -C {os.path.dirname(target_path)}"
            subprocess.run(shlex.split(cmd))
            
            # Clean up tar in target container
            cmd = f"docker exec {target_container} rm {dst_tar}"
            subprocess.run(shlex.split(cmd))
    
    except Exception as e:
        logger.error(f"Error during file transfer: {e}")
        return False, 0
    finally:
        # Clean up temp directory
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)
    
    transfer_end = time.time()
    transfer_time = transfer_end - transfer_start
    logger.info(f"\033[1;31mTIMER: {operation_name} completed in: \033[1;33m{transfer_time:.6f} seconds")
    
    return True, transfer_time


def main():
    """Main function to transfer files from encryptor to main container"""
    total_start = time.time()
    total_time = 0
    
    logger.info("Starting upload process from fhe-enc to fhe-main...")
    
    # Transfer results - now with flatten_directory=True to directly copy files to data folder
    success, upload_time1 = copy_between_containers_bash(
        source_container="fhe-main",
        source_path="/bdt/build/results/",
        target_container="fhe-dec",
        target_path="/bdt/build/data/",
        target_speed_mbps=30.0,
        operation_name="Upload results data",
        flatten_directory=True
    )
    total_time += upload_time1
    
    # Transfer cryptocontext - keep original directory structure
    success, upload_time2 = copy_between_containers_bash(
        source_container="fhe-main",
        source_path="/bdt/build/cryptocontext/",
        target_container="fhe-dec",
        target_path="/bdt/build/cryptocontext/",
        target_speed_mbps=30.0,
        operation_name="Upload cryptocontext",
        flatten_directory=True
    )
    total_time += upload_time2
    
    total_end = time.time()
    overall_time = total_end - total_start
    
    logger.info(f"\033[1;32m============================================")
    logger.info(f"\033[1;32mTOTAL UPLOAD TIME: \033[1;33m{total_time:.6f} seconds")
    logger.info(f"\033[1;32mOVERALL PROCESS TIME: \033[1;33m{overall_time:.6f} seconds")
    logger.info(f"\033[1;32m============================================")
def main2():
    """Main function to transfer files from encryptor to main container"""
    total_start = time.time()
    total_time = 0
    
    logger.info("Starting upload process from fhe-enc to fhe-main...")
    
    # Transfer results
    success, upload_time1 = copy_between_containers(
        source_container="fhe-enc",
        source_path="/bdt/build/results/",
        target_container="fhe-main",
        target_path="/bdt/build/data/",
        target_speed_mbps=30.0,
        operation_name="Upload results data"
    )
    total_time += upload_time1
    
    # Transfer cryptocontext
    success, upload_time2 = copy_between_containers(
        source_container="fhe-enc",
        source_path="/bdt/build/cryptocontext/",
        target_container="fhe-main",
        target_path="/bdt/build/cryptocontext/",
        target_speed_mbps=30.0,
        operation_name="Upload cryptocontext"
    )
    total_time += upload_time2
    
    total_end = time.time()
    overall_time = total_end - total_start
    
    logger.info(f"\033[1;32m============================================")
    logger.info(f"\033[1;32mTOTAL UPLOAD TIME: \033[1;33m{total_time:.6f} seconds")
    logger.info(f"\033[1;32mOVERALL PROCESS TIME: \033[1;33m{overall_time:.6f} seconds")
    logger.info(f"\033[1;32m============================================")

if __name__ == "__main__":
    main()