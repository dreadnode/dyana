# Fit Planning

`dyana fit` recommends a small set of models that are likely to fit the current machine.

Unlike `dyana trace`, this command is host-side only:

- it does not start Docker
- it does not run loaders
- it does not download models
- it does not execute artifacts

It is meant to answer a narrower question first: what is even worth trying on this hardware?

## What It Uses

The current prototype looks at:

- total system RAM
- detected NVIDIA GPU memory, if present
- Apple Silicon unified memory heuristics on `Darwin arm64`
- detected runtimes such as Dyana `automodel`, `ollama`, `llama.cpp`, and `mlx`
- a packaged local model and provider catalog

## Examples

Recommend coding-oriented models:

```bash
dyana fit --use-case coding --top-k 5
```

Get JSON output for automation:

```bash
dyana fit --use-case general --top-k 3 --json
```

Limit results to a specific runtime and budget:

```bash
dyana fit --use-case coding --runtime ollama --max-memory-gb 12
```

Prefer a Dyana-native execution path:

```bash
dyana fit --use-case coding --runtime automodel
```

Explain why some candidates were excluded:

```bash
dyana fit --use-case coding --explain-excluded
```

## Output

The text view shows:

- detected hardware summary
- detected runtimes
- ranked recommendations
- estimated memory use
- runtime and quantization choice
- a short rationale for each recommendation
- provider-specific artifact and invocation hints
- optional exclusion reasons for rejected candidates

The JSON view includes the same information in a machine-readable structure.

## Preferences

The planner supports a small set of opinionated controls:

- `--runtime` to limit results to `automodel`, `ollama`, `mlx`, or `llama_cpp`
- `--max-memory-gb` to cap the effective memory budget
- `--preference balanced|quality|speed` to nudge quantization ranking
- `--explain-excluded` to include a short rejection reason for excluded candidates

## Current Scope

This is intentionally lightweight. The prototype:

- uses simple fit heuristics instead of benchmark-backed throughput estimates
- ranks a packaged local catalog rather than a large external model index
- focuses on fit and practical starting points, not exhaustive provider support

The command is a planning tool. For real artifact execution and profiling, continue to use `dyana trace`.

When the selected provider is `automodel`, the recommendation includes a Dyana invocation hint using `dyana trace --loader automodel`.
