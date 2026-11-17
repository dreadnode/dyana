from __future__ import annotations

import argparse
import json
import math
import os
import re
import struct
import typing as t

DTYPE_SIZES: dict[str, int] = {
    "F16": 2,
    "F32": 4,
    "BF16": 2,
    "F64": 8,
    "I8": 1,
    "I16": 2,
    "I32": 4,
    "I64": 8,
    "U8": 1,
    "BOOL": 1,
}

MAX_HEADER_SIZE = 100 * 1024 * 1024  # 100MB


def validate_header(path: str) -> dict[str, t.Any]:
    errors: list[str] = []
    header_length = 0
    file_size = 0
    header_json: dict[str, t.Any] = {}

    try:
        file_size = os.path.getsize(path)
    except OSError as e:
        errors.append(f"cannot read file: {e}")
        return {
            "header_length": 0,
            "file_size": 0,
            "header_json": {},
            "errors": errors,
        }

    if file_size < 8:
        errors.append(f"file too small ({file_size} bytes), cannot read header length")
        return {
            "header_length": 0,
            "file_size": file_size,
            "header_json": {},
            "errors": errors,
        }

    with open(path, "rb") as f:
        header_length_bytes = f.read(8)
        header_length = struct.unpack("<Q", header_length_bytes)[0]

        if header_length == 0:
            errors.append("header length is zero")
            return {
                "header_length": 0,
                "file_size": file_size,
                "header_json": {},
                "errors": errors,
            }

        if header_length > MAX_HEADER_SIZE:
            errors.append(f"header length ({header_length:,} bytes) exceeds 100MB limit — possible header bomb")
            return {
                "header_length": header_length,
                "file_size": file_size,
                "header_json": {},
                "errors": errors,
            }

        if header_length + 8 > file_size:
            errors.append(f"header extends past end of file (header_length={header_length}, file_size={file_size})")
            return {
                "header_length": header_length,
                "file_size": file_size,
                "header_json": {},
                "errors": errors,
            }

        header_bytes = f.read(header_length)
        try:
            header_json = json.loads(header_bytes)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            errors.append(f"invalid JSON in header: {e}")
            return {
                "header_length": header_length,
                "file_size": file_size,
                "header_json": {},
                "errors": errors,
            }

    return {
        "header_length": header_length,
        "file_size": file_size,
        "header_json": header_json,
        "errors": errors,
    }


def analyze_tensors(header: dict[str, t.Any], data_start: int, file_size: int) -> dict[str, t.Any]:
    errors: list[str] = []
    warnings: list[str] = []
    info: list[str] = []

    tensor_entries: list[dict[str, t.Any]] = []
    dtype_distribution: dict[str, int] = {}
    total_data_bytes = 0

    data_size = file_size - data_start

    # collect all tensor entries (skip __metadata__)
    for name, entry in header.items():
        if name == "__metadata__":
            continue

        if not isinstance(entry, dict):
            errors.append(f"tensor '{name}': entry is not a dict")
            continue

        dtype = entry.get("dtype")
        shape = entry.get("shape")
        offsets = entry.get("data_offsets")

        # validate dtype
        if dtype not in DTYPE_SIZES:
            errors.append(f"tensor '{name}': unknown dtype '{dtype}'")
            continue

        # validate shape
        if not isinstance(shape, list) or not all(isinstance(s, int) and s >= 0 for s in shape):
            errors.append(f"tensor '{name}': invalid shape {shape}")
            continue

        # validate offsets
        if not isinstance(offsets, list) or len(offsets) != 2 or not all(isinstance(o, int) for o in offsets):
            errors.append(f"tensor '{name}': invalid data_offsets {offsets}")
            continue

        begin, end = offsets
        if begin > end:
            errors.append(f"tensor '{name}': begin offset ({begin}) > end offset ({end})")
            continue

        if end > data_size:
            errors.append(f"tensor '{name}': data_offsets [{begin}, {end}] exceed data section size ({data_size})")

        # check shape/size consistency
        expected_size = math.prod(shape) * DTYPE_SIZES[dtype] if shape else 0
        actual_size = end - begin
        if expected_size != actual_size:
            warnings.append(
                f"tensor '{name}': shape {shape} with dtype {dtype} expects {expected_size} bytes, "
                f"but data_offsets span {actual_size} bytes"
            )

        dtype_distribution[dtype] = dtype_distribution.get(dtype, 0) + 1
        total_data_bytes += actual_size
        tensor_entries.append(
            {
                "name": name,
                "dtype": dtype,
                "shape": shape,
                "begin": begin,
                "end": end,
            }
        )

    # detect overlapping byte ranges
    sorted_tensors = sorted(tensor_entries, key=lambda t: t["begin"])
    for i in range(len(sorted_tensors) - 1):
        curr = sorted_tensors[i]
        nxt = sorted_tensors[i + 1]
        if curr["end"] > nxt["begin"]:
            errors.append(
                f"overlapping tensors: '{curr['name']}' [{curr['begin']}:{curr['end']}] "
                f"overlaps with '{nxt['name']}' [{nxt['begin']}:{nxt['end']}]"
            )

    # detect gaps
    if sorted_tensors:
        if sorted_tensors[0]["begin"] > 0:
            info.append(f"gap of {sorted_tensors[0]['begin']} bytes at start of data section")
        for i in range(len(sorted_tensors) - 1):
            gap = sorted_tensors[i + 1]["begin"] - sorted_tensors[i]["end"]
            if gap > 0:
                info.append(
                    f"gap of {gap} bytes between '{sorted_tensors[i]['name']}' and '{sorted_tensors[i + 1]['name']}'"
                )
        last_end = sorted_tensors[-1]["end"]
        if last_end < data_size:
            info.append(f"gap of {data_size - last_end} bytes at end of data section")

    # sample tensors (first 10)
    sample_tensors = [{"name": t["name"], "dtype": t["dtype"], "shape": t["shape"]} for t in tensor_entries[:10]]

    return {
        "count": len(tensor_entries),
        "total_data_bytes": total_data_bytes,
        "dtype_distribution": dtype_distribution,
        "sample_tensors": sample_tensors,
        "errors": errors,
        "warnings": warnings,
        "info": info,
    }


def analyze_metadata(header: dict[str, t.Any]) -> dict[str, t.Any]:
    warnings: list[str] = []
    info: list[str] = []

    metadata = header.get("__metadata__")
    if metadata is None:
        return {"metadata": None, "warnings": warnings, "info": info}

    if not isinstance(metadata, dict):
        warnings.append(f"__metadata__ is not a dict (got {type(metadata).__name__})")
        return {"metadata": None, "warnings": warnings, "info": info}

    for key, value in metadata.items():
        if not isinstance(value, str):
            warnings.append(f"metadata key '{key}': value is {type(value).__name__}, expected string")
            continue

        if len(value) > 10240:
            warnings.append(f"metadata key '{key}': very long value ({len(value)} chars)")

        if re.search(r"https?://", value):
            info.append(f"metadata key '{key}': contains URL")

        if re.search(r"^[A-Za-z0-9+/]{100,}={0,2}$", value):
            info.append(f"metadata key '{key}': value looks like base64-encoded data")

    return {"metadata": dict(metadata), "warnings": warnings, "info": info}


if __name__ == "__main__":
    from dyana import Profiler  # type: ignore[attr-defined]

    parser = argparse.ArgumentParser(description="Analyze SafeTensors files for structural integrity")
    parser.add_argument("--safetensors", help="Path to SafeTensors file", required=True)
    args = parser.parse_args()
    profiler: Profiler = Profiler(gpu=False)

    if not os.path.exists(args.safetensors):
        profiler.track_error("safetensors", "SafeTensors file not found")
    else:
        # Stage 1: validate structure
        profiler.on_stage("validating_structure")
        result = validate_header(args.safetensors)

        for error in result["errors"]:
            profiler.track_error("structure", error)

        # Stage 2: parse header
        profiler.on_stage("parsing_header")
        header_json = result["header_json"]
        data_start = 8 + result["header_length"]

        profiler.track_extra(
            "file_structure",
            {
                "header_length": result["header_length"],
                "file_size": result["file_size"],
                "data_section_size": result["file_size"] - data_start if result["header_length"] > 0 else 0,
                "header_valid": len(result["errors"]) == 0,
            },
        )

        if header_json:
            # Stage 3: analyze tensors
            profiler.on_stage("analyzing_tensors")
            tensor_result = analyze_tensors(header_json, data_start, result["file_size"])

            for error in tensor_result["errors"]:
                profiler.track_error("tensor", error)
            for warning in tensor_result["warnings"]:
                profiler.track_warning("tensor", warning)

            profiler.track_extra(
                "tensor_summary",
                {
                    "count": tensor_result["count"],
                    "total_data_bytes": tensor_result["total_data_bytes"],
                    "dtype_distribution": tensor_result["dtype_distribution"],
                    "sample_tensors": tensor_result["sample_tensors"],
                },
            )

            # Stage 4: analyze metadata
            profiler.on_stage("analyzing_metadata")
            meta_result = analyze_metadata(header_json)

            for warning in meta_result["warnings"]:
                profiler.track_warning("metadata", warning)

            if meta_result["metadata"]:
                profiler.track_extra("metadata", meta_result["metadata"])

            # Collect all findings
            findings: dict[str, list[str]] = {
                "errors": result["errors"] + tensor_result["errors"],
                "warnings": tensor_result["warnings"] + meta_result["warnings"],
                "info": tensor_result["info"] + meta_result["info"],
            }
            profiler.track_extra("findings", findings)
