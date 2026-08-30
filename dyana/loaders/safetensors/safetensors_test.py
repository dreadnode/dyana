from __future__ import annotations

import json
import struct
import typing as t
from pathlib import Path

from dyana.loaders.loader import Loader
from dyana.loaders.safetensors.main import (
    analyze_metadata,
    analyze_tensors,
    validate_header,
)


def _make_safetensors(path: Path, header: dict[str, t.Any], data: bytes = b"") -> None:
    header_bytes = json.dumps(header).encode("utf-8")
    header_length = len(header_bytes)
    with open(path, "wb") as f:
        f.write(struct.pack("<Q", header_length))
        f.write(header_bytes)
        f.write(data)


class TestSafeTensorsLoaderSettings:
    def test_loader_loads(self) -> None:
        loader = Loader(name="safetensors", build=False)
        assert loader.settings is not None
        assert loader.settings.gpu is False

    def test_correct_arg_structure(self) -> None:
        loader = Loader(name="safetensors", build=False)
        assert loader.settings is not None
        assert loader.settings.args is not None
        assert len(loader.settings.args) == 1
        assert loader.settings.args[0].name == "safetensors"
        assert loader.settings.args[0].required is True
        assert loader.settings.args[0].volume is True


class TestValidateHeader:
    def test_valid_minimal(self, tmp_path: Path) -> None:
        path = tmp_path / "test.safetensors"
        header: dict[str, t.Any] = {
            "weight": {
                "dtype": "F32",
                "shape": [2, 3],
                "data_offsets": [0, 24],
            }
        }
        _make_safetensors(path, header, data=b"\x00" * 24)
        result = validate_header(str(path))
        assert result["errors"] == []
        assert result["header_json"] == header
        assert result["file_size"] > 0
        assert result["header_length"] > 0

    def test_header_bomb(self, tmp_path: Path) -> None:
        path = tmp_path / "bomb.safetensors"
        with open(path, "wb") as f:
            # header_length = 200MB
            f.write(struct.pack("<Q", 200 * 1024 * 1024))
            f.write(b"\x00" * 16)
        result = validate_header(str(path))
        assert len(result["errors"]) > 0
        assert "100MB" in result["errors"][0]

    def test_header_past_eof(self, tmp_path: Path) -> None:
        path = tmp_path / "truncated.safetensors"
        with open(path, "wb") as f:
            f.write(struct.pack("<Q", 1000))
            f.write(b"\x00" * 10)
        result = validate_header(str(path))
        assert len(result["errors"]) > 0
        assert "past end of file" in result["errors"][0]

    def test_invalid_json(self, tmp_path: Path) -> None:
        path = tmp_path / "badjson.safetensors"
        bad_json = b"not json at all!"
        with open(path, "wb") as f:
            f.write(struct.pack("<Q", len(bad_json)))
            f.write(bad_json)
        result = validate_header(str(path))
        assert len(result["errors"]) > 0
        assert "invalid JSON" in result["errors"][0]

    def test_empty_file(self, tmp_path: Path) -> None:
        path = tmp_path / "empty.safetensors"
        path.write_bytes(b"")
        result = validate_header(str(path))
        assert len(result["errors"]) > 0
        assert "too small" in result["errors"][0]

    def test_zero_length_header(self, tmp_path: Path) -> None:
        path = tmp_path / "zero.safetensors"
        with open(path, "wb") as f:
            f.write(struct.pack("<Q", 0))
        result = validate_header(str(path))
        assert len(result["errors"]) > 0
        assert "zero" in result["errors"][0]


class TestAnalyzeTensors:
    def test_valid_tensors(self) -> None:
        header: dict[str, t.Any] = {
            "weight": {
                "dtype": "F32",
                "shape": [2, 3],
                "data_offsets": [0, 24],
            },
            "bias": {
                "dtype": "F32",
                "shape": [3],
                "data_offsets": [24, 36],
            },
        }
        result = analyze_tensors(header, data_start=100, file_size=136)
        assert result["count"] == 2
        assert result["total_data_bytes"] == 36
        assert result["errors"] == []
        assert result["warnings"] == []

    def test_unknown_dtype(self) -> None:
        header: dict[str, t.Any] = {
            "weight": {
                "dtype": "BFLOAT256",
                "shape": [2, 3],
                "data_offsets": [0, 24],
            }
        }
        result = analyze_tensors(header, data_start=100, file_size=124)
        assert len(result["errors"]) > 0
        assert "unknown dtype" in result["errors"][0]

    def test_overlapping_offsets(self) -> None:
        header: dict[str, t.Any] = {
            "a": {
                "dtype": "F32",
                "shape": [10],
                "data_offsets": [0, 40],
            },
            "b": {
                "dtype": "F32",
                "shape": [10],
                "data_offsets": [20, 60],
            },
        }
        result = analyze_tensors(header, data_start=100, file_size=160)
        assert any("overlapping" in e for e in result["errors"])

    def test_out_of_bounds_offsets(self) -> None:
        header: dict[str, t.Any] = {
            "weight": {
                "dtype": "F32",
                "shape": [2, 3],
                "data_offsets": [0, 24],
            }
        }
        # file_size too small to contain data
        result = analyze_tensors(header, data_start=100, file_size=110)
        assert any("exceed" in e for e in result["errors"])

    def test_shape_size_mismatch(self) -> None:
        header: dict[str, t.Any] = {
            "weight": {
                "dtype": "F32",
                "shape": [2, 3],
                "data_offsets": [0, 100],  # should be 24
            }
        }
        result = analyze_tensors(header, data_start=100, file_size=200)
        assert len(result["warnings"]) > 0
        assert "expects" in result["warnings"][0]

    def test_zero_dimension_tensor(self) -> None:
        header: dict[str, t.Any] = {
            "empty": {
                "dtype": "F32",
                "shape": [0],
                "data_offsets": [0, 0],
            }
        }
        result = analyze_tensors(header, data_start=100, file_size=100)
        assert result["count"] == 1
        assert result["errors"] == []

    def test_empty_header(self) -> None:
        result = analyze_tensors({}, data_start=100, file_size=100)
        assert result["count"] == 0
        assert result["errors"] == []

    def test_metadata_skipped(self) -> None:
        header: dict[str, t.Any] = {
            "__metadata__": {"format": "pt"},
            "weight": {
                "dtype": "F32",
                "shape": [4],
                "data_offsets": [0, 16],
            },
        }
        result = analyze_tensors(header, data_start=100, file_size=116)
        assert result["count"] == 1


class TestAnalyzeMetadata:
    def test_no_metadata(self) -> None:
        result = analyze_metadata({"weight": {"dtype": "F32"}})
        assert result["metadata"] is None
        assert result["warnings"] == []

    def test_clean_metadata(self) -> None:
        header: dict[str, t.Any] = {"__metadata__": {"format": "pt", "framework": "pytorch"}}
        result = analyze_metadata(header)
        assert result["metadata"] == {"format": "pt", "framework": "pytorch"}
        assert result["warnings"] == []
        assert result["info"] == []

    def test_non_string_values(self) -> None:
        header: dict[str, t.Any] = {"__metadata__": {"count": 42}}
        result = analyze_metadata(header)
        assert len(result["warnings"]) > 0
        assert "expected string" in result["warnings"][0]

    def test_very_long_values(self) -> None:
        header: dict[str, t.Any] = {"__metadata__": {"blob": "x" * 20000}}
        result = analyze_metadata(header)
        assert len(result["warnings"]) > 0
        assert "very long" in result["warnings"][0]

    def test_suspicious_url(self) -> None:
        header: dict[str, t.Any] = {"__metadata__": {"source": "https://evil.example.com/payload"}}
        result = analyze_metadata(header)
        assert any("URL" in i for i in result["info"])
