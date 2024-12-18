from bcc import BPF
import argparse
import ctypes

# eBPF C program for tracing CUDA memory allocations
bpf_program = """
#include <uapi/linux/ptrace.h>

int trace_entry(struct pt_regs *ctx) {
    bpf_trace_printk("CUDA op\\n");
    return 0;
}
"""


class CUDAMemoryTracer:
    def __init__(self, cuda_lib_path="/usr/local/cuda/lib64/libcudart.so"):
        targets = {
            "/usr/local/cuda/lib64/libcudart.so": [
                "cudaMalloc",
                "cudaFree",
                "cudaMalloc3D",
                "cudaMalloc3DArray",
                "cudaMallocArray",
                "cudaMallocHost",
                "cudaMallocManaged",
                "cudaMallocMipmappedArray",
                "cudaMallocPitch",
            ],
            "/usr/local/cuda/lib64/stubs/libcuda.so": [
                "cuMemAlloc",
                "cuMemAlloc_v2",
                "cuMemFree",
            ],
        }

        self.b = BPF(text=bpf_program)

        for lib_name, functions in targets.items():
            for func in functions:
                self.b.attach_uprobe(name=lib_name, sym=func, fn_name="trace_entry")
                print(f"Attached uprobe to {lib_name}::{func}")

    def start_tracing(self):
        """
        Start tracing CUDA memory allocations
        """
        print("Starting CUDA Memory Allocation Tracing...")
        print("Press Ctrl+C to stop.")

        # Print trace events
        while True:
            try:
                # Read trace events
                task, pid, cpu, flags, ts, msg = self.b.trace_fields()
                print(f"[{ts}] {msg.decode('utf-8')}")
            except KeyboardInterrupt:
                break


def main():
    parser = argparse.ArgumentParser(description="CUDA Memory Allocation Tracer")
    parser.add_argument(
        "--cuda-lib",
        default="/usr/local/cuda/lib64/libcudart.so",
        help="Path to CUDA runtime library",
    )
    args = parser.parse_args()

    # Check if running with root privileges
    if os.geteuid() != 0:
        print("This script requires root privileges. Please run with sudo.")
        sys.exit(1)

    # Initialize and start tracer
    tracer = CUDAMemoryTracer(cuda_lib_path=args.cuda_lib)
    tracer.start_tracing()


if __name__ == "__main__":
    import os
    import sys

    main()
