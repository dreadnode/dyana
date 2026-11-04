from __future__ import annotations

import os
import platform
import shutil
import subprocess

from dyana.fit.models import HardwareProfile, RuntimeAvailability


def _safe_round(value: float) -> float:
    return round(value, 1)


def detect_total_ram_gb() -> float:
    if hasattr(os, "sysconf") and "SC_PAGE_SIZE" in os.sysconf_names and "SC_PHYS_PAGES" in os.sysconf_names:
        page_size = int(os.sysconf("SC_PAGE_SIZE"))
        pages = int(os.sysconf("SC_PHYS_PAGES"))
        return _safe_round((page_size * pages) / (1024**3))

    return 0.0


def detect_runtimes() -> RuntimeAvailability:
    return RuntimeAvailability(
        automodel=True,
        ollama=shutil.which("ollama") is not None,
        llama_cpp=shutil.which("llama-cli") is not None or shutil.which("llama-server") is not None,
        mlx=platform.system() == "Darwin" and platform.machine() == "arm64",
    )


def detect_nvidia_gpu() -> tuple[str | None, int, float | None]:
    binary = shutil.which("nvidia-smi")
    if not binary:
        return None, 0, None

    try:
        output = subprocess.check_output(
            [
                binary,
                "--query-gpu=name,memory.total",
                "--format=csv,noheader,nounits",
            ],
            text=True,
        )
    except Exception:
        return None, 0, None

    rows = [row.strip() for row in output.splitlines() if row.strip()]
    if not rows:
        return None, 0, None

    names: list[str] = []
    total_mb = 0.0
    for row in rows:
        name, mem = [part.strip() for part in row.split(",", maxsplit=1)]
        names.append(name)
        total_mb += float(mem)

    return names[0], len(rows), _safe_round(total_mb / 1024)


def detect_hardware() -> HardwareProfile:
    system = platform.system()
    arch = platform.machine()
    ram_gb = detect_total_ram_gb()
    gpu_name, gpu_count, total_vram_gb = detect_nvidia_gpu()
    runtimes = detect_runtimes()
    unified_memory = system == "Darwin" and arch == "arm64"

    if unified_memory and total_vram_gb is None:
        total_vram_gb = _safe_round(ram_gb * 0.7)
        if gpu_name is None:
            gpu_name = "Apple Silicon"
            gpu_count = 1

    return HardwareProfile(
        platform=system,
        arch=arch,
        total_ram_gb=ram_gb,
        gpu_name=gpu_name,
        gpu_count=gpu_count,
        total_vram_gb=total_vram_gb,
        unified_memory=unified_memory,
        runtimes=runtimes,
    )
