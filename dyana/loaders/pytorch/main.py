from __future__ import annotations

import argparse
import os
import pickletools
import re
import typing as t
import zipfile

# Opcodes that can execute arbitrary code
DANGEROUS_OPCODES: dict[str, str] = {
    "GLOBAL": "imports a module attribute (can import arbitrary code)",
    "INST": "instantiates a class (can execute arbitrary constructors)",
    "OBJ": "builds an object (can execute arbitrary constructors)",
    "NEWOBJ": "creates a new object (can call arbitrary __new__)",
    "NEWOBJ_EX": "creates a new object with kwargs (can call arbitrary __new__)",
    "REDUCE": "calls a callable (can execute arbitrary functions)",
    "BUILD": "calls __setstate__ (can trigger arbitrary code via object reconstruction)",
    "STACK_GLOBAL": "imports a module attribute from stack (can import arbitrary code)",
}

# Known-safe modules/functions commonly seen in legitimate PyTorch checkpoints
KNOWN_SAFE_GLOBALS: set[str] = {
    "torch._utils._rebuild_tensor_v2",
    "torch._utils._rebuild_parameter",
    "torch._utils._rebuild_parameter_with_state",
    "torch.FloatStorage",
    "torch.LongStorage",
    "torch.IntStorage",
    "torch.ShortStorage",
    "torch.DoubleStorage",
    "torch.HalfStorage",
    "torch.ByteStorage",
    "torch.CharStorage",
    "torch.BFloat16Storage",
    "torch.ComplexFloatStorage",
    "torch.ComplexDoubleStorage",
    "torch.storage._load_from_bytes",
    "torch.nn.modules.module.Module",
    "collections.OrderedDict",
    "_codecs.encode",
    "torch.Size",
    "torch.device",
    "torch.dtype",
    "torch.float16",
    "torch.float32",
    "torch.float64",
    "torch.bfloat16",
    "torch.int8",
    "torch.int16",
    "torch.int32",
    "torch.int64",
    "torch.uint8",
    "torch.bool",
    "torch.complex64",
    "torch.complex128",
    "torch._utils._rebuild_tensor_v3",
    "torch._utils._rebuild_device_tensor_v2",
}

# Module prefixes that are suspicious
SUSPICIOUS_MODULE_PREFIXES: list[str] = [
    "os.",
    "subprocess.",
    "shutil.",
    "sys.",
    "builtins.",
    "importlib.",
    "ctypes.",
    "socket.",
    "http.",
    "urllib.",
    "requests.",
    "webbrowser.",
    "code.",
    "eval",
    "exec",
    "compile",
    "__builtin__.",
    "nt.",
    "posix.",
    "signal.",
]


def check_zip_structure(path: str) -> dict[str, t.Any]:
    """Check if the file is a valid ZIP archive (PyTorch format) or legacy pickle."""
    errors: list[str] = []
    info: list[str] = []
    is_zip = False
    is_legacy_pickle = False
    zip_entries: list[dict[str, t.Any]] = []

    try:
        is_zip = zipfile.is_zipfile(path)
    except OSError as e:
        errors.append(f"cannot read file: {e}")
        return {
            "is_zip": False,
            "is_legacy_pickle": False,
            "zip_entries": [],
            "errors": errors,
            "info": info,
        }

    if is_zip:
        try:
            with zipfile.ZipFile(path, "r") as zf:
                for zi in zf.infolist():
                    zip_entries.append(
                        {
                            "filename": zi.filename,
                            "file_size": zi.file_size,
                            "compress_size": zi.compress_size,
                        }
                    )
                    # check for path traversal in zip entries
                    if ".." in zi.filename or zi.filename.startswith("/"):
                        errors.append(f"suspicious zip entry path: '{zi.filename}' (possible path traversal)")
        except zipfile.BadZipFile as e:
            errors.append(f"corrupted zip file: {e}")
    else:
        # check if it's a legacy pickle file (pre-zip PyTorch format)
        try:
            with open(path, "rb") as f:
                magic = f.read(2)
                # pickle protocol opcodes: \x80 = PROTO
                if magic and magic[0] == 0x80:
                    is_legacy_pickle = True
                    info.append("file is legacy pickle format (not ZIP-based)")
        except OSError as e:
            errors.append(f"cannot read file: {e}")

    return {
        "is_zip": is_zip,
        "is_legacy_pickle": is_legacy_pickle,
        "zip_entries": zip_entries,
        "errors": errors,
        "info": info,
    }


def scan_pickle_opcodes(data: bytes) -> dict[str, t.Any]:
    """Scan pickle bytecode for dangerous opcodes without executing it."""
    errors: list[str] = []
    warnings: list[str] = []
    info: list[str] = []

    dangerous_ops: list[dict[str, str]] = []
    global_imports: list[str] = []
    all_opcodes: dict[str, int] = {}

    try:
        ops = list(pickletools.genops(data))
    except Exception as e:
        errors.append(f"failed to disassemble pickle: {e}")
        return {
            "dangerous_ops": [],
            "global_imports": [],
            "all_opcodes": {},
            "errors": errors,
            "warnings": warnings,
            "info": info,
        }

    for opcode, arg, _pos in ops:
        name = opcode.name
        all_opcodes[name] = all_opcodes.get(name, 0) + 1

        if name in DANGEROUS_OPCODES:
            entry: dict[str, str] = {
                "opcode": name,
                "reason": DANGEROUS_OPCODES[name],
            }
            if arg is not None:
                entry["arg"] = str(arg)
            dangerous_ops.append(entry)

        # Track GLOBAL/STACK_GLOBAL imports specifically
        if name in ("GLOBAL", "STACK_GLOBAL") and arg is not None:
            # pickletools returns "module attr" (space-separated), normalize to "module.attr"
            normalized = str(arg).replace(" ", ".")
            global_imports.append(normalized)

    # Classify global imports
    suspicious_globals: list[str] = []
    unknown_globals: list[str] = []

    for g in global_imports:
        if g in KNOWN_SAFE_GLOBALS:
            continue
        is_suspicious = False
        for prefix in SUSPICIOUS_MODULE_PREFIXES:
            if g.startswith(prefix) or g == prefix.rstrip("."):
                suspicious_globals.append(g)
                is_suspicious = True
                break
        if not is_suspicious and g not in KNOWN_SAFE_GLOBALS:
            unknown_globals.append(g)

    if suspicious_globals:
        for g in suspicious_globals:
            errors.append(f"suspicious global import: '{g}'")

    if unknown_globals:
        for g in unknown_globals:
            warnings.append(f"unknown global import: '{g}'")

    # Summarize
    safe_count = len(global_imports) - len(suspicious_globals) - len(unknown_globals)
    if global_imports:
        info.append(
            f"{len(global_imports)} global imports: "
            f"{safe_count} known-safe, "
            f"{len(unknown_globals)} unknown, "
            f"{len(suspicious_globals)} suspicious"
        )

    return {
        "dangerous_ops": dangerous_ops,
        "global_imports": global_imports,
        "all_opcodes": all_opcodes,
        "errors": errors,
        "warnings": warnings,
        "info": info,
    }


def analyze_pytorch_file(path: str) -> dict[str, t.Any]:
    """Full analysis of a PyTorch checkpoint file."""
    errors: list[str] = []
    warnings: list[str] = []
    info: list[str] = []

    file_size = os.path.getsize(path)
    zip_result = check_zip_structure(path)

    errors.extend(zip_result["errors"])
    info.extend(zip_result["info"])

    pickle_scan: dict[str, t.Any] | None = None
    data_files: list[dict[str, t.Any]] = []

    if zip_result["is_zip"]:
        try:
            with zipfile.ZipFile(path, "r") as zf:
                for zi in zf.infolist():
                    if zi.filename.endswith(".pkl") or zi.filename.endswith("data.pkl"):
                        # Scan pickle data inside ZIP
                        pkl_data = zf.read(zi.filename)
                        pickle_scan = scan_pickle_opcodes(pkl_data)
                        errors.extend(pickle_scan["errors"])
                        warnings.extend(pickle_scan["warnings"])
                        info.extend(pickle_scan["info"])
                    elif re.match(r".*/data/\d+$", zi.filename):
                        data_files.append(
                            {
                                "name": zi.filename,
                                "size": zi.file_size,
                            }
                        )
        except Exception as e:
            errors.append(f"failed to read zip contents: {e}")

    elif zip_result["is_legacy_pickle"]:
        try:
            with open(path, "rb") as f:
                pkl_data = f.read()
            pickle_scan = scan_pickle_opcodes(pkl_data)
            errors.extend(pickle_scan["errors"])
            warnings.extend(pickle_scan["warnings"])
            info.extend(pickle_scan["info"])
        except Exception as e:
            errors.append(f"failed to read pickle data: {e}")

    else:
        errors.append("file is neither a ZIP archive nor a pickle file — not a valid PyTorch checkpoint")

    return {
        "file_size": file_size,
        "is_zip": zip_result["is_zip"],
        "is_legacy_pickle": zip_result["is_legacy_pickle"],
        "zip_entries": zip_result["zip_entries"],
        "data_files": data_files,
        "pickle_scan": pickle_scan,
        "errors": errors,
        "warnings": warnings,
        "info": info,
    }


if __name__ == "__main__":
    from dyana import Profiler  # type: ignore[attr-defined]

    parser = argparse.ArgumentParser(description="Analyze PyTorch checkpoint files for security issues")
    parser.add_argument("--pytorch", help="Path to PyTorch checkpoint file", required=True)
    args = parser.parse_args()
    profiler: Profiler = Profiler(gpu=False)

    if not os.path.exists(args.pytorch):
        profiler.track_error("pytorch", "PyTorch checkpoint file not found")
    else:
        # Stage 1: check file structure
        profiler.on_stage("checking_structure")
        result = analyze_pytorch_file(args.pytorch)

        for error in result["errors"]:
            profiler.track_error("pytorch", error)
        for warning in result["warnings"]:
            profiler.track_warning("pytorch", warning)

        profiler.track_extra(
            "file_structure",
            {
                "file_size": result["file_size"],
                "is_zip": result["is_zip"],
                "is_legacy_pickle": result["is_legacy_pickle"],
                "zip_entries": result["zip_entries"],
                "data_files": result["data_files"],
            },
        )

        # Stage 2: report pickle analysis
        profiler.on_stage("analyzing_pickle")
        if result["pickle_scan"]:
            scan = result["pickle_scan"]

            profiler.track_extra(
                "pickle_analysis",
                {
                    "global_imports": scan["global_imports"],
                    "dangerous_ops_count": len(scan["dangerous_ops"]),
                    "dangerous_ops": scan["dangerous_ops"][:20],
                    "opcode_distribution": scan["all_opcodes"],
                },
            )

        # Collect findings
        profiler.track_extra(
            "findings",
            {
                "errors": result["errors"],
                "warnings": result["warnings"],
                "info": result["info"],
            },
        )
