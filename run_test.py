#!/usr/bin/env python3
# filepath: /home/nima/run_Test.py
import argparse
import subprocess
import sys
import time
from datetime import datetime

def format_time(seconds):
    """Format time in seconds to a human-readable string with microsecond precision"""
    return f"{seconds:.6f}"

def clean_volumes():
    """Clean docker volumes for the FHE containers"""
    start_time = time.time()
    #print("Cleaning volumes...")
    
    subprocess.run(["docker", "exec", "fhe-enc", "sh", "-c", 
                    "rm -rf /bdt/build/results/* /bdt/build/private_data/* /bdt/build/cryptocontext/*"], 
                   check=True)
    
    subprocess.run(["docker", "exec", "fhe-main", "sh", "-c", 
                    "rm -rf /bdt/build/results/*"], 
                   check=True)
    
    end_time = time.time()
    execution_time = end_time - start_time
    
    #print("Cleaning volumes done!")
    #print("============ Results ===============")
    
    subprocess.run(["docker", "exec", "fhe-enc", "ls", 
                    "/bdt/build/results/", "/bdt/build/private_data/", "/bdt/build/cryptocontext/"], 
                   check=True)
    
    #print("=============================")
    #print(f"⏱️ Clean volumes execution time: {format_time(execution_time)}")
    return execution_time

def run_encryption(security, depth, modulus):
    """Run the encryption process with the provided parameters"""
    print("Running FHE encryption...")
    print("=============================")
    
    start_time = time.time()
    subprocess.run(["docker", "exec", "fhe-enc", "./fhe-enc", 
                    # "--security", str(security), 
                    # "--depth", str(depth), 
                    # "--modulus", str(modulus)], 
    ],
                   check=True)
    end_time = time.time()
    execution_time = end_time - start_time
    
    print(f"Encryption execution time: {format_time(execution_time)}")
    return execution_time

def run_user_vm():
    """Run the user VM script"""
    print("Running user VM...")
    print("=============================")
    start_time = time.time()
    subprocess.run(["python3.9", "user_vm.py"], check=True)
    end_time = time.time()
    execution_time = end_time - start_time
    
    print(f"User VM execution time: {format_time(execution_time)}")
    return execution_time

def run_fhe_main():
    """Run the FHE main process"""
    print("Running FHE main...")
    print("=============================")
    
    start_time = time.time()
    subprocess.run(["docker", "exec", "fhe-main", "./fhe-main"], check=True)
    end_time = time.time()
    execution_time = end_time - start_time
    
    print(f"FHE main execution time: {format_time(execution_time)}")
    return execution_time

def run_server_vm():
    """Run the server VM script"""
    print("Running server VM...")
    print("=============================")
    start_time = time.time()
    subprocess.run(["python3.9", "server_vm.py"], check=True)
    end_time = time.time()
    execution_time = end_time - start_time
    
    print(f"Server VM execution time: {format_time(execution_time)}")
    return execution_time

def run_decryption():
    """Run the decryption process"""
    print("Running FHE decryption...")
    print("=============================")
    
    start_time = time.time()
    subprocess.run(["docker", "exec", "fhe-dec", "./fhe-dec"], check=True)
    end_time = time.time()
    execution_time = end_time - start_time
    
    print(f"Decryption execution time: {format_time(execution_time)}")
    return execution_time

def main():
    """Main function to parse arguments and run the FHE workflow"""
    parser = argparse.ArgumentParser(description='Run FHE workflow with specified parameters')
    
    parser.add_argument('--security', type=int, required=True,
                        help='Security parameter for FHE')
    parser.add_argument('--depth', type=int, required=True,
                        help='Depth parameter for FHE')
    parser.add_argument('--modulus', type=int, required=True,
                        help='Modulus parameter for FHE')
    
    args = parser.parse_args()
    
    try:
        overall_start = time.time()
        #timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        #print(f"\n🚀 Starting FHE workflow at {timestamp}")
        print(f"Parameters: Security={args.security}, Depth={args.depth}, Modulus={args.modulus}\n")
        
        times = {}
        times['clean'] = clean_volumes()
        times['encrypt'] = run_encryption(args.security, args.depth, args.modulus)
        times['user_vm'] = run_user_vm()
        times['fhe_main'] = run_fhe_main()
        times['server_vm'] = run_server_vm()
        times['decrypt'] = run_decryption()
        
        overall_end = time.time()
        overall_time = overall_end - overall_start
        
        # Print timing summary
        print("\n" + "="*50)
        print("EXECUTION TIME SUMMARY")
        print("="*50)
        print(f"Clean volumes:  {format_time(times['clean'])}")
        print(f"Encryption:     {format_time(times['encrypt'])}")
        print(f"User VM:        {format_time(times['user_vm'])}")
        print(f"FHE Main:       {format_time(times['fhe_main'])}")
        print(f"Server VM:      {format_time(times['server_vm'])}")
        print(f"Decryption:     {format_time(times['decrypt'])}")
        print("-"*50)
        print(f"TOTAL TIME:     {format_time(overall_time)}")
        print("="*50)
        
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()