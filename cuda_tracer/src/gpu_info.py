import torch
from typing import Dict, Any

def get_gpu_info() -> Dict[str, Any]:
    """Get A100 GPU information"""
    if not torch.cuda.is_available():
        return {"error": "CUDA not available"}

    return {
        "gpu_name": torch.cuda.get_device_name(),
        "gpu_capability": torch.cuda.get_device_capability(),
        "memory": {
            "total": torch.cuda.get_device_properties(0).total_memory / (1024**3),  # GB
            "available": torch.cuda.memory_allocated() / (1024**3),
            "cached": torch.cuda.memory_reserved() / (1024**3)
        },
        "compute_mode": torch.cuda.get_device_properties(0).compute_mode,
        "max_threads_per_block": torch.cuda.get_device_properties(0).max_threads_per_block
    }
