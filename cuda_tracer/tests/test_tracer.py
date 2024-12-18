import pytest
import torch
from cuda_tracer import CUDATracer

def test_cuda_available():
    assert torch.cuda.is_available(), "CUDA is not available"

def test_basic_tracing():
    tracer = CUDATracer()

    # Simple CUDA operation
    x = torch.randn(1000, 1000).cuda()
    y = torch.matmul(x, x)

    stats = tracer.get_cuda_stats()
    assert stats['total_calls'] > 0, "No CUDA calls detected"
    assert 'memory' in stats['calls_by_category'], "Memory operations not detected"

def test_model_tracing():
    tracer = CUDATracer()

    # Small test model
    model = torch.nn.Linear(100, 100).cuda()
    input_tensor = torch.randn(32, 100).cuda()
    output = model(input_tensor)

    stats = tracer.get_cuda_stats()
    assert stats['total_calls'] > 0, "No CUDA calls detected"
    assert 'execution' in stats['calls_by_category'], "Kernel executions not detected"

def test_error_handling():
    tracer = CUDATracer()

    # Force an error with invalid CUDA operation
    try:
        x = torch.randn(1000, 1000).cuda()
        y = torch.matmul(x, torch.randn(100, 100).cuda())  # Mismatched dimensions
    except:
        pass

    stats = tracer.get_cuda_stats()
    assert len(stats['errors']) > 0, "Error not detected"
