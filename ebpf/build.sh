#!/bin/bash

# Create builder instance
docker buildx create --name multiarch-builder --use

# Bootstrap builder
docker buildx inspect --bootstrap

# Build and push for multiple architectures
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t yourusername/ebpf-model-tracer:latest \
  --push \
  .

# Or build locally without pushing
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t ebpf-model-tracer:latest \
  --load \
  .