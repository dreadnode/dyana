FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
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
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Don't create a non-root user - run as root for BPF operations
WORKDIR /app

# Fix Python path for BCC
ENV PYTHONPATH=/usr/lib/python3/dist-packages

# Copy files
COPY ebpf_tracer.py /app/
COPY loader.py /app/
COPY requirements.txt /app/

# Install Python dependencies
RUN pip3 install --no-cache-dir -r /app/requirements.txt

# Make scripts executable
RUN chmod +x /app/ebpf_tracer.py /app/loader.py

# Set capabilities for BPF operations
RUN setcap cap_sys_admin+eip /usr/bin/python3.10

ENTRYPOINT ["python3", "/app/ebpf_tracer.py"]