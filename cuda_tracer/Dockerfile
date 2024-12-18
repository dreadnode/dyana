FROM nvidia/cuda:11.8.0-devel-ubuntu22.04

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3-pip \
    python3.10 \
    python3.10-dev \
    linux-headers-generic \
    bpfcc-tools \
    python3-bpfcc \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install poetry
RUN pip3 install poetry

# Set working directory
WORKDIR /app/cuda_tracer

# Copy entire project first
COPY . .

# Install dependencies and project
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi

# Default command
CMD ["poetry", "run", "pytest", "tests/"]
