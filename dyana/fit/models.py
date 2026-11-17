from __future__ import annotations

from pydantic import BaseModel


class RuntimeAvailability(BaseModel):
    automodel: bool = True
    ollama: bool = False
    llama_cpp: bool = False
    mlx: bool = False


class HardwareProfile(BaseModel):
    platform: str
    arch: str
    total_ram_gb: float
    gpu_name: str | None = None
    gpu_count: int = 0
    total_vram_gb: float | None = None
    unified_memory: bool = False
    runtimes: RuntimeAvailability


class ProviderSpec(BaseModel):
    id: str
    name: str
    runtime_key: str
    supported_modes: list[str]
    preferred_on: list[str] = []
    quantizations: list[str]
    artifact_hint: str
    invocation_template: str


class ModelSpec(BaseModel):
    id: str
    name: str
    family: str
    use_cases: list[str]
    params_b: float
    context_k: int
    supported_providers: list[str]
    supported_quantizations: list[str]
    aliases: list[str] = []


class FitCatalog(BaseModel):
    providers: list[ProviderSpec]
    models: list[ModelSpec]


class FitRecommendation(BaseModel):
    model_id: str
    model: str
    family: str
    use_case: str
    runtime: str
    provider: str
    quantization: str
    mode: str
    estimated_memory_gb: float
    headroom_gb: float
    score: int
    rationale: str
    artifact_hint: str
    invocation_hint: str


class ExcludedCandidate(BaseModel):
    model_id: str
    model: str
    provider: str
    reason: str


class FitResult(BaseModel):
    hardware: HardwareProfile
    use_case: str
    recommendations: list[FitRecommendation]
    runtime_filter: str | None = None
    max_memory_gb: float | None = None
    excluded: list[ExcludedCandidate] = []
