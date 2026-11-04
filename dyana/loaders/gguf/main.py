import argparse
import os
import re
import typing as t

# Patterns indicating SSTI / code execution attempts in Jinja2 templates
MALICIOUS_PATTERNS = [
    (r"__class__", "Python dunder access: __class__"),
    (r"__base__", "Python dunder access: __base__"),
    (r"__mro__", "Python dunder access: __mro__"),
    (r"__subclasses__", "Python dunder access: __subclasses__"),
    (r"__globals__", "Python dunder access: __globals__"),
    (r"__builtins__", "Python dunder access: __builtins__"),
    (r"\bos\.", "OS module access"),
    (r"\bsubprocess\b", "Subprocess module reference"),
    (r"\beval\s*\(", "eval() call"),
    (r"\bexec\s*\(", "exec() call"),
    (r"\bimport\s+", "Import statement"),
    (r"\|attr\b", "Jinja2 attr filter (SSTI vector)"),
]

# Patterns indicating obfuscation techniques
OBFUSCATION_PATTERNS = [
    (r"\bbase64\b", "Base64 encoding reference"),
    (r"\\x[0-9a-fA-F]{2}", "Hex escape sequence"),
    (r"\\u[0-9a-fA-F]{4}", "Unicode escape sequence"),
    (r"\bchr\s*\(", "chr() character construction"),
    (r"\+\s*['\"]|['\"]\s*\+", "String concatenation in template"),
]

# Patterns that are suspicious but may be legitimate
SUSPICIOUS_PATTERNS = [
    (r"\{%\s*if\b", "Conditional logic in template"),
    (r"\{%\s*for\b", "Loop construct in template"),
    (r"\|\s*\w+\s*\|\s*\w+", "Chained filter usage"),
]


DANGEROUS_DUNDER_ATTRS = {
    "__class__",
    "__base__",
    "__bases__",
    "__mro__",
    "__subclasses__",
    "__globals__",
    "__builtins__",
    "__import__",
    "__init__",
    "__code__",
    "__func__",
    "__self__",
    "__module__",
    "__dict__",
    "__getattr__",
    "__setattr__",
    "__delattr__",
}

DANGEROUS_FILTER_NAMES = {"attr", "map", "select", "reject", "groupby"}

DANGEROUS_CALL_NAMES = {"eval", "exec", "compile", "execfile", "input", "__import__", "getattr", "setattr", "delattr"}


def _analyze_ast(template: str) -> dict[str, list[str]]:
    """Walk the Jinja2 AST to detect structural security issues."""
    findings: dict[str, list[str]] = {"errors": [], "warnings": [], "info": []}

    try:
        from jinja2 import nodes
        from jinja2.sandbox import SandboxedEnvironment
    except ImportError:
        return findings

    try:
        env = SandboxedEnvironment()
        ast = env.parse(template)
    except Exception as e:
        findings["errors"].append(f"Sandbox validation failed: {e}")
        return findings

    # Walk every node in the AST
    for node in ast.find_all(nodes.Node):
        # Attribute access on dunder names
        if isinstance(node, nodes.Getattr):
            if node.attr in DANGEROUS_DUNDER_ATTRS:
                findings["errors"].append(f"AST: dangerous attribute access '{node.attr}'")
            elif node.attr.startswith("__") and node.attr.endswith("__"):
                findings["warnings"].append(f"AST: dunder attribute access '{node.attr}'")

        # Function calls to dangerous builtins
        elif isinstance(node, nodes.Call):
            callee = node.node
            if isinstance(callee, nodes.Name) and callee.name in DANGEROUS_CALL_NAMES:
                findings["errors"].append(f"AST: dangerous call to '{callee.name}()'")
            elif isinstance(callee, nodes.Getattr) and callee.attr in DANGEROUS_CALL_NAMES:
                findings["errors"].append(f"AST: dangerous call to '.{callee.attr}()'")

        # Filter usage
        elif isinstance(node, nodes.Filter):
            if node.name in DANGEROUS_FILTER_NAMES:
                findings["warnings"].append(f"AST: potentially dangerous filter '|{node.name}'")

    return findings


def analyze_chat_template(template: str) -> dict[str, list[str]]:
    """Analyze a Jinja2 chat template for security issues.

    Uses two complementary approaches:
    - Regex scanning catches patterns in raw text (including comments and obfuscation)
    - AST walking catches structural issues regardless of formatting

    Returns a dict with keys 'errors', 'warnings', and 'info' containing lists of finding strings.
    """
    findings: dict[str, list[str]] = {"errors": [], "warnings": [], "info": []}

    # Layer 1: Regex scanning for known patterns in raw text
    for pattern, description in MALICIOUS_PATTERNS:
        if re.search(pattern, template):
            findings["errors"].append(f"Malicious pattern detected: {description}")

    for pattern, description in OBFUSCATION_PATTERNS:
        if re.search(pattern, template):
            findings["warnings"].append(f"Obfuscation detected: {description}")

    for pattern, description in SUSPICIOUS_PATTERNS:
        if re.search(pattern, template):
            findings["info"].append(f"Suspicious pattern: {description}")

    # Layer 2: AST-based structural analysis
    ast_findings = _analyze_ast(template)
    for key in ("errors", "warnings", "info"):
        findings[key].extend(ast_findings[key])

    return findings


def extract_metadata(reader: t.Any) -> dict[str, str | int | float | None]:
    """Extract key metadata fields from a GGUF file."""
    metadata: dict[str, str | int | float | None] = {}

    key_fields = {
        "general.architecture": "architecture",
        "general.name": "model_name",
        "general.quantization_version": "quantization_version",
        "general.file_type": "file_type",
        "tokenizer.chat_template": "chat_template",
    }

    # Dynamic context length keys by architecture
    context_length_suffixes = [
        ".context_length",
        ".block_count",
        ".embedding_length",
        ".head_count",
    ]

    for field in reader.fields:
        field_name = str(field)

        if field_name in key_fields:
            field_obj = reader.fields[field_name]
            parts = field_obj.parts
            # The value is typically in the last part(s) after the metadata key
            if len(parts) > 0:
                data = field_obj.data
                if len(data) == 1:
                    metadata[key_fields[field_name]] = data[0].item() if hasattr(data[0], "item") else str(data[0])
                elif len(data) > 1:
                    # For string fields, decode the bytes
                    try:
                        metadata[key_fields[field_name]] = bytes(data).decode("utf-8")
                    except (UnicodeDecodeError, TypeError):
                        metadata[key_fields[field_name]] = str(data)
        else:
            # Check for architecture-specific context length
            for suffix in context_length_suffixes:
                if field_name.endswith(suffix):
                    field_obj = reader.fields[field_name]
                    data = field_obj.data
                    if len(data) == 1:
                        key = suffix.lstrip(".")
                        metadata[key] = data[0].item() if hasattr(data[0], "item") else int(data[0])

    metadata["total_metadata_fields"] = len(reader.fields)
    return metadata


def validate_file_structure(path: str) -> dict[str, str | int | bool]:
    """Validate GGUF file structure: magic bytes, version, size."""
    result: dict[str, str | int | bool] = {}

    file_size = os.path.getsize(path)
    result["file_size_bytes"] = file_size

    with open(path, "rb") as f:
        magic = f.read(4)
        result["magic_valid"] = magic == b"GGUF"
        result["magic_hex"] = magic.hex()

        if len(magic) < 4:
            result["error"] = "File too small to contain GGUF header"
            return result

        # Version is a uint32 LE at offset 4
        version_bytes = f.read(4)
        if len(version_bytes) == 4:
            version = int.from_bytes(version_bytes, byteorder="little")
            result["version"] = version

    return result


if __name__ == "__main__":
    from dyana import Profiler  # type: ignore[attr-defined]

    parser = argparse.ArgumentParser(description="Analyze a GGUF model file")
    parser.add_argument("--gguf", help="Path to GGUF file", required=True)
    args = parser.parse_args()
    profiler: Profiler = Profiler(gpu=False)

    if not os.path.exists(args.gguf):
        profiler.track_error("gguf", "GGUF file not found")
    else:
        try:
            # Stage 1: Validate file structure
            structure = validate_file_structure(args.gguf)
            profiler.on_stage("validating_structure")
            profiler.track_extra("file_structure", structure)

            if not structure.get("magic_valid"):
                profiler.track_error("gguf", f"Invalid GGUF magic bytes: {structure.get('magic_hex', 'unknown')}")
            else:
                # Stage 2: Parse GGUF with the official reader
                from gguf import GGUFReader

                reader = GGUFReader(args.gguf)
                profiler.on_stage("parsing_gguf")

                # Stage 3: Extract metadata
                metadata = extract_metadata(reader)
                profiler.on_stage("extracting_metadata")

                # Store metadata (excluding the raw template which goes to analysis)
                chat_template = metadata.pop("chat_template", None)
                profiler.track_extra("metadata", metadata)

                # Stage 4: Analyze chat template
                if chat_template and isinstance(chat_template, str):
                    profiler.track_extra("chat_template_length", len(chat_template))
                    findings = analyze_chat_template(chat_template)
                    profiler.on_stage("analyzing_template")

                    for error in findings["errors"]:
                        profiler.track_error(f"template.{error[:50]}", error)

                    for warning in findings["warnings"]:
                        profiler.track_warning(f"template.{warning[:50]}", warning)

                    profiler.track_extra("template_findings", findings)
                else:
                    profiler.on_stage("analyzing_template")
                    profiler.track_extra("chat_template_length", 0)
                    profiler.track_extra("template_findings", {"errors": [], "warnings": [], "info": []})

                # Stage 5: Analyze tensors
                tensor_count = len(reader.tensors)
                tensor_info = []
                for tensor in reader.tensors[:20]:  # Sample first 20
                    tensor_info.append(
                        {
                            "name": str(tensor.name),
                            "shape": [int(d) for d in tensor.shape],
                            "type": str(tensor.tensor_type),
                        }
                    )

                profiler.on_stage("analyzing_tensors")
                profiler.track_extra("tensor_count", tensor_count)
                profiler.track_extra("tensor_sample", tensor_info)

        except Exception as e:
            profiler.track_error("gguf", str(e))
