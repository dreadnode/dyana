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

# Copy project files
COPY pyproject.toml poetry.lock ./

# Install dependencies
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi

# Install package in editable mode
RUN pip install -e .

# Copy source code
COPY . .

# Default command
CMD ["poetry", "run", "pytest", "tests/"]
