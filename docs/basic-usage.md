# Basic Usage

Show the available loaders:

```bash
dyana loaders
```

Show help for a specific loader:

```bash
dyana help automodel
```

Plan model choices against the current machine before tracing:

```bash
dyana fit --use-case coding --top-k 5
```

Emit machine-readable fit recommendations:

```bash
dyana fit --use-case general --json
```

Restrict the planner to a specific runtime and memory budget:

```bash
dyana fit --use-case coding --runtime ollama --max-memory-gb 12 --explain-excluded
```

Plan specifically for Dyana's built-in automodel loader:

```bash
dyana fit --use-case coding --runtime automodel
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

`dyana fit` is host-side only. It does not start Docker, pull models, or execute artifacts. It is intended as a quick planning step before a real traced run.

## Default Safeguards

Network access is disabled by default for loader containers. Allow it explicitly when needed:

```bash
dyana trace ... --allow-network
```

The shared input volume is mounted read-only by default. Allow writes explicitly when needed:

```bash
dyana trace ... --allow-volume-write
```
