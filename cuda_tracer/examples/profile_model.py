from cuda_tracer import CUDATracer
import torch
from transformers import AutoModel

def main():
    # Initialize CUDA tracer
    tracer = CUDATracer()

    # Load and run a model
    model = AutoModel.from_pretrained("bert-base-uncased").cuda()

    # Get CUDA profiling data
    stats = tracer.get_cuda_stats()
    print("CUDA Statistics:")
    print(f"Total CUDA calls: {stats['total_calls']}")
    print("\nCalls by category:")
    for category, count in stats['calls_by_category'].items():
        print(f"  {category}: {count}")

if __name__ == "__main__":
    main()
