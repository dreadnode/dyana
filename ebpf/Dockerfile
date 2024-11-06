FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies first
RUN apt-get update && apt-get install -y \
    python3 \
    python3-dev \
    python3-pip \
    bpfcc-tools \
    python3-bpfcc \
    libbpfcc \
    libbpfcc-dev \
    linux-headers-generic \
    kmod \
    gcc \
    make \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash appuser
RUN mkdir /app && chown appuser:appuser /app

# Switch to root temporarily to install system-wide packages
USER root

# Setup kernel headers
RUN mkdir -p /lib/modules/$(uname -r)/build && \
    ln -s /usr/src/linux-headers-$(uname -r) /lib/modules/$(uname -r)/build

# Fix Python path for BCC
ENV PYTHONPATH=/usr/lib/python3/dist-packages

# Copy files with correct permissions
COPY --chown=appuser:appuser ebpf_tracer.py /app/
COPY --chown=appuser:appuser loader.py /app/
COPY --chown=appuser:appuser requirements.txt /app/

# Install Python dependencies
RUN pip3 install --no-cache-dir -r /app/requirements.txt

# Make scripts executable
RUN chmod +x /app/ebpf_tracer.py /app/loader.py

# Switch to non-root user
USER appuser
WORKDIR /app

# Set the entrypoint
ENTRYPOINT ["python3", "/app/ebpf_tracer.py"]