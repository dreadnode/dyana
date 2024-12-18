# CUDA Tracer

A specialized tool for profiling CUDA operations in ML models, focusing on A100 GPU analysis.

- [CUDA Tracer](#cuda-tracer)
  - [Installation](#installation)
    - [Prerequisites](#prerequisites)
    - [Using Poetry (Recommended)](#using-poetry-recommended)
    - [Using Docker](#using-docker)
  - [Development](#development)
  - [Features](#features)
  - [Testing](#testing)
  - [Example Usage](#example-usage)
  - [Project Structure](#project-structure)
  - [Requirements](#requirements)
  - [Troubleshooting](#troubleshooting)
    - [Common Issues](#common-issues)

## Installation

### Prerequisites

```bash
# 1. Install NVIDIA Container Toolkit
distribution=$(. /etc/os-release;echo $ID$VERSION_ID) \
   && curl -s -L https://nvidia.github.io/libnvidia-container/gpgkey | sudo apt-key add - \
   && curl -s -L https://nvidia.github.io/libnvidia-container/$distribution/libnvidia-container.list | sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list

sudo apt-get update
sudo apt-get install -y nvidia-container-toolkit
sudo nvidia-ctk runtime configure --runtime=docker
sudo systemctl restart docker

# 2. Install kernel headers (required for BPF)
sudo apt-get install -y linux-headers-generic

# 3. Validate setup
python3 scripts/check_setup.py
```

### Using Poetry (Recommended)
```bash
# Install Poetry if you haven't already
curl -sSL https://install.python-poetry.org | python3 -

# Install dependencies and create virtual environment
poetry install

# Activate virtual environment
poetry shell
```

### Using Docker

```bash
# Build and run tests
docker-compose up --build

# For development shell
docker-compose run --rm cuda-tracer bash
```

## Development

```bash
# Install all dependencies including dev dependencies
poetry install

# Format code
poetry run black .
poetry run isort .

# Type checking
poetry run mypy src/

# Run tests
poetry run pytest tests/
```

## Features

- Real-time CUDA API call tracing
- A100 GPU-specific metrics
- Memory allocation tracking
- Kernel launch profiling
- PyTorch integration
- Low-overhead eBPF-based tracing

## Testing

```bash
# Run all tests
poetry run pytest

# Single test file
poetry run pytest tests/test_tracer.py -v

# With coverage
poetry run pytest tests/ --cov=cuda_tracer
```

## Example Usage

```python
from cuda_tracer import CUDATracer
import torch

# Initialize tracer
tracer = CUDATracer()

# Run CUDA operations
x = torch.randn(1000, 1000).cuda()
y = torch.matmul(x, x)

# Get statistics
stats = tracer.get_cuda_stats()
print(f"CUDA calls: {stats['total_calls']}")
```

## Project Structure
```
cuda_tracer/
├── src/
│   ├── tracer.py         # Main tracing logic
│   ├── categories.py     # CUDA operation categories
│   ├── gpu_info.py      # A100 specific metrics
│   └── bpf_programs.py  # eBPF tracing code
├── tests/
├── examples/
├── pyproject.toml        # Poetry dependency management
├── .env                  # Environment configuration
└── docker-compose.yml
```

## Requirements

- NVIDIA A100 GPU
- CUDA 11.8+
- Linux kernel 5.4+
- Python 3.8+
- PyTorch 2.0+
- Poetry 1.4+

## Troubleshooting

### Common Issues

1. **ModuleNotFoundError: No module named 'cuda_tracer'**
   ```bash
   # Inside container or virtualenv
   pip install -e .
   ```

2. **NVIDIA runtime error**
   ```bash
   # Test NVIDIA Docker setup
   docker run --rm --gpus all nvidia/cuda:11.8.0-base-ubuntu22.04 nvidia-smi
   ```

3. **BPF/eBPF errors**
   ```bash
   # Check kernel headers
   dpkg -s linux-headers-generic
   ```