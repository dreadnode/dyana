from __future__ import annotations

from dyana.fit.catalog import load_catalog
from dyana.fit.models import (
    ExcludedCandidate,
    FitCatalog,
    FitRecommendation,
    FitResult,
    HardwareProfile,
    ModelSpec,
    ProviderSpec,
)

QUANTIZATION_BYTES_PER_PARAM: dict[str, float] = {
    "Q4_K_M": 0.62,
    "Q6_K": 0.85,
    "Q8_0": 1.05,
    "F16": 2.10,
}


def _safe_round(value: float) -> float:
    return round(value, 1)


def estimate_model_memory_gb(params_b: float, quantization: str) -> float:
    bytes_per_param = QUANTIZATION_BYTES_PER_PARAM[quantization]
    return _safe_round(params_b * bytes_per_param * 1.15)


def _runtime_enabled(hardware: HardwareProfile, provider: ProviderSpec) -> bool:
    return bool(getattr(hardware.runtimes, provider.runtime_key, False))


def _mode_capacity_gb(hardware: HardwareProfile, mode: str) -> float:
    if mode == "unified":
        return _safe_round(hardware.total_ram_gb * 0.7)
    if mode == "gpu":
        return hardware.total_vram_gb or 0.0
    return _safe_round(hardware.total_ram_gb * 0.6)


def _provider_viable_modes(hardware: HardwareProfile, provider: ProviderSpec) -> list[str]:
    modes: list[str] = []
    for mode in provider.supported_modes:
        if mode == "unified" and hardware.unified_memory:
            modes.append(mode)
        elif mode == "gpu" and hardware.total_vram_gb and hardware.total_vram_gb > 0:
            modes.append(mode)
        elif mode == "cpu":
            modes.append(mode)
    return modes


def _use_case_bonus(model: ModelSpec, requested_use_case: str) -> int:
    if requested_use_case in model.use_cases:
        return 18
    if requested_use_case == "coding" and "reasoning" in model.use_cases:
        return 8
    return 0


def _runtime_bonus(provider: ProviderSpec, mode: str) -> int:
    score = 0
    if mode in provider.preferred_on:
        score += 6
    runtime_bonuses = {"mlx": 4, "ollama": 3, "llama_cpp": 2}
    return score + runtime_bonuses.get(provider.runtime_key, 0)


def _provider_map(catalog: FitCatalog) -> dict[str, ProviderSpec]:
    return {provider.id: provider for provider in catalog.providers}


def _preferred_quantizations(preference: str) -> list[str]:
    if preference == "quality":
        return ["F16", "Q8_0", "Q6_K", "Q4_K_M"]
    if preference == "speed":
        return ["Q4_K_M", "Q6_K", "Q8_0", "F16"]
    return ["Q8_0", "Q6_K", "Q4_K_M", "F16"]


def _quantization_bonus(quantization: str, preference: str) -> int:
    quality_bonus = {"F16": 7, "Q8_0": 5, "Q6_K": 3, "Q4_K_M": 1}
    speed_bonus = {"Q4_K_M": 7, "Q6_K": 5, "Q8_0": 3, "F16": 1}
    balanced_bonus = {"Q8_0": 5, "Q6_K": 4, "Q4_K_M": 3, "F16": 2}
    if preference == "quality":
        return quality_bonus[quantization]
    if preference == "speed":
        return speed_bonus[quantization]
    return balanced_bonus[quantization]


def recommend_models(
    hardware: HardwareProfile,
    use_case: str = "general",
    top_k: int = 5,
    runtime: str | None = None,
    max_memory_gb: float | None = None,
    preference: str = "balanced",
    explain_excluded: bool = False,
    catalog: FitCatalog | None = None,
) -> FitResult:
    active_catalog = catalog or load_catalog()
    providers = _provider_map(active_catalog)
    recommendations: list[FitRecommendation] = []
    excluded: list[ExcludedCandidate] = []

    for model in active_catalog.models:
        best: FitRecommendation | None = None
        model_excluded_reasons: list[ExcludedCandidate] = []
        for provider_id in model.supported_providers:
            provider = providers[provider_id]
            if runtime and provider.runtime_key != runtime:
                model_excluded_reasons.append(
                    ExcludedCandidate(
                        model_id=model.id,
                        model=model.name,
                        provider=provider.runtime_key,
                        reason=f"runtime filter excludes provider '{provider.runtime_key}'",
                    )
                )
                continue
            if not _runtime_enabled(hardware, provider):
                model_excluded_reasons.append(
                    ExcludedCandidate(
                        model_id=model.id,
                        model=model.name,
                        provider=provider.runtime_key,
                        reason=f"runtime '{provider.runtime_key}' is not available on this host",
                    )
                )
                continue

            for mode in _provider_viable_modes(hardware, provider):
                capacity_gb = _mode_capacity_gb(hardware, mode)
                if max_memory_gb is not None:
                    capacity_gb = min(capacity_gb, max_memory_gb)

                shared_quants = [quant for quant in _preferred_quantizations(preference) if quant in model.supported_quantizations and quant in provider.quantizations]
                if not shared_quants:
                    model_excluded_reasons.append(
                        ExcludedCandidate(
                            model_id=model.id,
                            model=model.name,
                            provider=provider.runtime_key,
                            reason="no shared quantization between model and provider",
                        )
                    )
                    continue
                for quantization in shared_quants:
                    estimated_memory_gb = estimate_model_memory_gb(model.params_b, quantization)
                    headroom_gb = _safe_round(capacity_gb - estimated_memory_gb)
                    if headroom_gb < 0:
                        if explain_excluded:
                            model_excluded_reasons.append(
                                ExcludedCandidate(
                                    model_id=model.id,
                                    model=model.name,
                                    provider=provider.runtime_key,
                                    reason=(
                                        f"{quantization} needs ~{estimated_memory_gb} GiB but only "
                                        f"{capacity_gb} GiB is available in {mode} mode"
                                    ),
                                )
                            )
                        continue

                    score = 20
                    score += _use_case_bonus(model, use_case)
                    score += _runtime_bonus(provider, mode)
                    score += min(int(headroom_gb * 1.5), 12)
                    score += min(model.context_k // 32, 6)
                    score += _quantization_bonus(quantization, preference)

                    rationale = (
                        f"Fits in {mode} memory with ~{headroom_gb} GiB headroom using {quantization}; "
                        f"good match for {use_case} via {provider.name}."
                    )
                    candidate = FitRecommendation(
                        model_id=model.id,
                        model=model.name,
                        family=model.family,
                        use_case=use_case,
                        runtime=provider.runtime_key,
                        provider=provider.name,
                        quantization=quantization,
                        mode=mode,
                        estimated_memory_gb=estimated_memory_gb,
                        headroom_gb=headroom_gb,
                        score=min(score, 100),
                        rationale=rationale,
                        artifact_hint=provider.artifact_hint,
                        invocation_hint=provider.invocation_template.format(model_id=model.aliases[0] if model.aliases else model.id),
                    )
                    if best is None or candidate.score > best.score:
                        best = candidate

        if best is not None:
            recommendations.append(best)
        elif explain_excluded and model_excluded_reasons:
            excluded.append(model_excluded_reasons[0])

    recommendations.sort(key=lambda item: (-item.score, item.estimated_memory_gb, item.model))
    return FitResult(
        hardware=hardware,
        use_case=use_case,
        recommendations=recommendations[:top_k],
        runtime_filter=runtime,
        max_memory_gb=max_memory_gb,
        excluded=excluded[:top_k] if explain_excluded else [],
    )


def fit_result_json(result: FitResult) -> str:
    return result.model_dump_json(indent=2)
