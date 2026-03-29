# Basic Usage

Show the available loaders:

```bash
dyana loaders
```

Show help for a specific loader:

```bash
dyana help automodel
```

Create a trace file for a loader run:

```bash
dyana trace --loader automodel ... --output trace.json
```

Save artifacts from the container:

```bash
dyana trace --loader pip --package botocore --save /usr/local/bin/jp.py --save-to ./artifacts
```

Override the default Tracee events with a custom policy:

```bash
dyana trace --loader automodel ... --policy examples/network_only_policy.yml
```

Show a summary of a trace file:

```bash
dyana summary --trace-path trace.json
```

## Default Safeguards

Network access is disabled by default for loader containers. Allow it explicitly when needed:

```bash
dyana trace ... --allow-network
```

The shared input volume is mounted read-only by default. Allow writes explicitly when needed:

```bash
dyana trace ... --allow-volume-write
```
