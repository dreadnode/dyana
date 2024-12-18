#!/usr/bin/env python3
import sys
import subprocess
from typing import List, Tuple

def check_nvidia_docker() -> Tuple[bool, str]:
    try:
        out = subprocess.check_output(["docker", "run", "--rm", "--gpus", "all",
                                     "nvidia/cuda:11.8.0-base-ubuntu22.04", "nvidia-smi"])
        return True, "NVIDIA Docker runtime is properly configured"
    except Exception as e:
        return False, f"NVIDIA Docker runtime issue: {str(e)}"

def check_kernel_headers() -> Tuple[bool, str]:
    try:
        subprocess.check_output(["dpkg", "-s", "linux-headers-generic"])
        return True, "Kernel headers are installed"
    except:
        return False, "Missing kernel headers. Run: sudo apt-get install linux-headers-generic"

def main():
    checks = [
        check_nvidia_docker,
        check_kernel_headers,
    ]

    all_passed = True
    for check in checks:
        passed, msg = check()
        print(f"{'✓' if passed else '✗'} {msg}")
        all_passed = all_passed and passed

    sys.exit(0 if all_passed else 1)

if __name__ == "__main__":
    main()
