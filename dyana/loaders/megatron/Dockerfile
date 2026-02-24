FROM nvcr.io/nvidia/pytorch:26.01-py3

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    git \
    ca-certificates \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create required directories for multiprocessing
RUN mkdir -p /dev/shm && \
    mkdir -p /tmp/pytorch_extensions && \
    mkdir -p /run/shm && \
    chmod -R 777 /dev/shm /tmp/pytorch_extensions /run/shm

# Create ALL required directories for IPC and shared memory
RUN mkdir -p /dev/shm && \
    mkdir -p /run/shm && \
    mkdir -p /tmp/pytorch_extensions && \
    mkdir -p /tmp/.pytorch_jit_cache && \
    mkdir -p /tmp/transformers && \
    chmod -R 777 /dev/shm /run/shm /tmp/pytorch_extensions /tmp/.pytorch_jit_cache /tmp/transformers

# Only verify PyTorch version during build (not CUDA)
RUN python3 -c "import torch; print(f'PyTorch version: {torch.__version__}')"

# Create working directory
RUN mkdir -p /app/workspace

# Copy files in correct order
COPY requirements.txt /app/workspace/
COPY *.py /app/workspace/
COPY dyana-requirements*.txt /app/workspace/

WORKDIR /app/workspace

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install Megatron-LM
RUN git clone --depth 1 --branch dmc https://github.com/NVIDIA/Megatron-LM.git /app/Megatron-LM && \
    cd /app/Megatron-LM && \
    pip install -e .

ENV PYTHONPATH=/app/workspac:/app/Megatron-LM:$PYTHONPATH

ENTRYPOINT ["python3", "-W", "ignore", "main.py"]