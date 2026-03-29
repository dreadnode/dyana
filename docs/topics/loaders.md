# Loaders

Dyana offers a set of loaders for different file types, each with its own arguments and examples. By default, each loader runs in an isolated, offline container.

To view the available loaders and their descriptions:

```bash
dyana loaders
```

To show the help menu for a specific loader:

```bash
dyana help <loader>
```

## AutoModel

Loads and profiles machine learning models compatible with [AutoModel and AutoTokenizer](https://huggingface.co/transformers/v3.0.2/model_doc/auto.html).

**Optional Build Arguments:** `--extra-requirements`

### Arguments

| Argument | Description | Default | Required |
|----------|-------------|---------|----------|
| `--model` | Path to the model to profile. | `None` | yes |
| `--input` | Input for the model. | `This is an example sentence.` | no |
| `--low-memory` | Perform tokenizer and model initialization without loading weights. | `None` | no |

### Examples

```bash
dyana trace --loader automodel --model /path/to/model --input "This is an example sentence."
```

```bash
dyana trace --model /path/to/model --input "This is an example sentence."
```

```bash
dyana trace --model tohoku-nlp/bert-base-japanese --input "This is an example sentence." --extra-requirements "protobuf fugashi ipadic"
```

```bash
dyana trace --model /path/to/model --low-memory
```

## Ollama

Loads and profiles models via an Ollama server. Local models on the host machine are mounted and shared with the container.

**Requires Network:** no

### Arguments

| Argument | Description | Default | Required |
|----------|-------------|---------|----------|
| `--model` | Name of the Ollama model to profile. | `None` | yes |
| `--input` | Input for the model. | `This is an example sentence.` | no |

### Example

```bash
ollama pull deepseek-r1:1.5b && dyana trace --loader ollama --model deepseek-r1:1.5b
```

## LoRA

Loads LoRA adapters via PEFT.

**Optional Build Arguments:** `--extra-requirements`

### Arguments

| Argument | Description | Default | Required |
|----------|-------------|---------|----------|
| `--adapter` | Path to the LoRA adapter to profile. | `None` | yes |

### Example

```bash
dyana trace --loader lora --adapter /path/to/adapter
```

## ELF

Loads and profiles ELF executable files.

### Arguments

| Argument | Description | Default | Required |
|----------|-------------|---------|----------|
| `--elf` | Path to the executable file to run. | `None` | yes |

### Examples

```bash
dyana trace --loader elf --elf /path/to/linux_executable
```

```bash
dyana trace --loader elf --elf /path/to/linux_executable --platform linux/amd64
```

```bash
dyana trace --loader elf --elf /path/to/linux_executable --allow-network
```

## Pickle

Loads and profiles Python pickle files.

**Optional Build Arguments:** `--extra-requirements`

### Arguments

| Argument | Description | Default | Required |
|----------|-------------|---------|----------|
| `--pickle` | Path to the python pickle file to deserialize. | `None` | yes |
| `--extra-requirements` | Extra pip requirements (comma-separated list). | `None` | no |

### Examples

```bash
dyana trace --loader pickle --pickle /path/to/file.pickle
```

```bash
dyana trace --loader pickle --pickle /path/to/model.pkl --extra-requirements "torch"
```

```bash
dyana trace --loader pickle --pickle /path/to/model.pkl --extra-requirements "torch,torchvision"
```

```bash
dyana trace --loader pickle --pickle /path/to/file.pickle --allow-network
```

## Python

Loads and profiles serialized Python scripts.

**Requires Network:** no

**Optional Build Arguments:** `--extra-requirements`

### Arguments

| Argument | Description | Default | Required |
|----------|-------------|---------|----------|
| `--script` | Path to the script to profile. | `None` | yes |

### Examples

```bash
dyana trace --loader python --script /path/to/file.py
```

```bash
dyana trace --loader python --script /path/to/file.py --allow-network
```

## PIP

Loads and profiles Python package installation via PIP.

**Requires Network:** yes

**Optional Build Arguments:** `--extra-dependencies`

### Arguments

| Argument | Description | Default | Required |
|----------|-------------|---------|----------|
| `--package` | PIP compatible package name or expression. | `None` | yes |

### Examples

```bash
dyana trace --loader pip --package requests
```

```bash
dyana trace --loader pip --package requests==2.28.2
```

```bash
dyana trace --loader pip --package foobar --extra-dependencies "gcc"
```

## JS

Loads and profiles JavaScript files.

**Optional Build Arguments:** `--extra-requirements`

### Arguments

| Argument | Description | Default | Required |
|----------|-------------|---------|----------|
| `--script` | Path to the script to profile. | `None` | yes |

### Examples

```bash
dyana trace --loader js --script /path/to/file.js
```

```bash
dyana trace --loader js --script /path/to/file.js --allow-network
```

## NPM

Loads and profiles NodeJS package installation via NPM.

**Requires Network:** yes

**Optional Build Arguments:** `--extra-dependencies`

### Arguments

| Argument | Description | Default | Required |
|----------|-------------|---------|----------|
| `--package` | NPM compatible package name or expression. | `None` | yes |

### Examples

```bash
dyana trace --loader npm --package express
```

```bash
dyana trace --loader npm --package express@1.0.0
```

```bash
dyana trace --loader npm --package express --extra-dependencies "axios"
```

## Website

Opens a website in a headless browser and profiles its performance.

**Requires Network:** yes

### Arguments

| Argument | Description | Default | Required |
|----------|-------------|---------|----------|
| `--url` | URL to open. | `None` | yes |
| `--screenshot` | Save a screenshot of the page. | `None` | no |
| `--wait-for` | CSS selector to wait for before profiling. | `None` | no |
| `--wait-for-timeout` | Timeout in seconds for page load and element wait. | `None` | no |
| `--performance-log` | Enable advanced performance logging. | `None` | no |

### Examples

```bash
dyana trace --loader website --url https://www.google.com
```

```bash
dyana trace --loader website --url https://www.google.com --screenshot
```

```bash
dyana trace --loader website --url https://www.google.com --wait-for "body"
```

## Megatron

Loads and profiles Megatron-LM DMC models for efficient inference.

**Optional Build Arguments:** `--extra-requirements`

### Arguments

| Argument | Description | Default | Required |
|----------|-------------|---------|----------|
| `--model` | Path to model checkpoint. The tokenizer is auto-detected from the same directory when not provided explicitly. | `None` | yes |
| `--size` | Model size such as `7B` or `13B`. | `None` | no |
| `--input` | Input text for inference. | `This is an example prompt.` | no |
| `--tokenizer` | Explicit path to a tokenizer file. | `None` | no |

### Examples

```bash
dyana trace --loader megatron --model /path/to/model.pt --size 7B
```

```bash
dyana trace --loader megatron --model /path/to/model.pt --size 7B --tokenizer /path/to/tokenizer.model
```
