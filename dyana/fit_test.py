from unittest.mock import patch

from dyana.fit import (
    HardwareProfile,
    RuntimeAvailability,
    detect_hardware,
    detect_nvidia_gpu,
    estimate_model_memory_gb,
    load_catalog,
    recommend_models,
)


class TestEstimateModelMemory:
    def test_q4_estimate(self) -> None:
        assert estimate_model_memory_gb(7.0, "Q4_K_M") > 0

    def test_f16_larger_than_q4(self) -> None:
        assert estimate_model_memory_gb(7.0, "F16") > estimate_model_memory_gb(7.0, "Q4_K_M")


class TestDetectNvidiaGpu:
    def test_no_binary(self) -> None:
        with patch("dyana.fit.hardware.shutil.which", return_value=None):
            assert detect_nvidia_gpu() == (None, 0, None)

    def test_parses_multiple_gpus(self) -> None:
        with (
            patch("dyana.fit.hardware.shutil.which", return_value="/usr/bin/nvidia-smi"),
            patch(
                "dyana.fit.hardware.subprocess.check_output",
                return_value="NVIDIA RTX 4090, 24564\nNVIDIA RTX 4090, 24564\n",
            ),
        ):
            name, count, total_vram_gb = detect_nvidia_gpu()
            assert name == "NVIDIA RTX 4090"
            assert count == 2
            assert total_vram_gb is not None
            assert total_vram_gb > 40


class TestDetectHardware:
    def test_detects_apple_unified_memory(self) -> None:
        with (
            patch("dyana.fit.hardware.platform.system", return_value="Darwin"),
            patch("dyana.fit.hardware.platform.machine", return_value="arm64"),
            patch("dyana.fit.hardware.detect_total_ram_gb", return_value=64.0),
            patch("dyana.fit.hardware.detect_nvidia_gpu", return_value=(None, 0, None)),
            patch("dyana.fit.hardware.detect_runtimes", return_value=RuntimeAvailability(mlx=True)),
        ):
            hardware = detect_hardware()
            assert hardware.unified_memory is True
            assert hardware.gpu_name == "Apple Silicon"
            assert hardware.total_vram_gb == 44.8

    def test_detects_standard_linux_host(self) -> None:
        with (
            patch("dyana.fit.hardware.platform.system", return_value="Linux"),
            patch("dyana.fit.hardware.platform.machine", return_value="x86_64"),
            patch("dyana.fit.hardware.detect_total_ram_gb", return_value=32.0),
            patch("dyana.fit.hardware.detect_nvidia_gpu", return_value=("RTX 4090", 1, 24.0)),
            patch(
                "dyana.fit.hardware.detect_runtimes",
                return_value=RuntimeAvailability(ollama=True, llama_cpp=False, mlx=False),
            ),
        ):
            hardware = detect_hardware()
            assert hardware.platform == "Linux"
            assert hardware.gpu_count == 1
            assert hardware.total_vram_gb == 24.0
            assert hardware.runtimes.ollama is True


class TestRecommendModels:
    def test_catalog_loads_from_data_files(self) -> None:
        catalog = load_catalog()
        assert len(catalog.providers) >= 1
        assert len(catalog.models) >= 1

    def test_prefers_coding_models(self) -> None:
        hardware = HardwareProfile(
            platform="Linux",
            arch="x86_64",
            total_ram_gb=64.0,
            gpu_name="RTX 4090",
            gpu_count=1,
            total_vram_gb=24.0,
            runtimes=RuntimeAvailability(ollama=True),
        )

        result = recommend_models(hardware, use_case="coding", top_k=3)

        assert len(result.recommendations) == 3
        assert any("Coder" in recommendation.model for recommendation in result.recommendations)
        assert result.recommendations[0].score >= result.recommendations[-1].score
        assert result.recommendations[0].artifact_hint
        assert result.recommendations[0].invocation_hint

    def test_automodel_runtime_filter_works(self) -> None:
        hardware = HardwareProfile(
            platform="Linux",
            arch="x86_64",
            total_ram_gb=64.0,
            gpu_name="RTX 4090",
            gpu_count=1,
            total_vram_gb=24.0,
            runtimes=RuntimeAvailability(automodel=True),
        )

        result = recommend_models(hardware, use_case="coding", runtime="automodel", top_k=2)

        assert len(result.recommendations) == 2
        assert all(recommendation.runtime == "automodel" for recommendation in result.recommendations)
        assert all("dyana trace --loader automodel" in recommendation.invocation_hint for recommendation in result.recommendations)

    def test_returns_no_recommendations_for_tiny_machine(self) -> None:
        hardware = HardwareProfile(
            platform="Linux",
            arch="x86_64",
            total_ram_gb=1.0,
            gpu_name=None,
            gpu_count=0,
            total_vram_gb=None,
            runtimes=RuntimeAvailability(),
        )

        result = recommend_models(hardware, use_case="general", top_k=5)
        assert result.recommendations == []

    def test_cpu_only_mode_works(self) -> None:
        hardware = HardwareProfile(
            platform="Linux",
            arch="x86_64",
            total_ram_gb=24.0,
            gpu_name=None,
            gpu_count=0,
            total_vram_gb=None,
            runtimes=RuntimeAvailability(llama_cpp=True),
        )

        result = recommend_models(hardware, use_case="general", top_k=2)
        assert len(result.recommendations) == 2
        assert all(recommendation.mode == "cpu" for recommendation in result.recommendations)

    def test_runtime_filter_limits_results(self) -> None:
        hardware = HardwareProfile(
            platform="Darwin",
            arch="arm64",
            total_ram_gb=24.0,
            gpu_name="Apple Silicon",
            gpu_count=1,
            total_vram_gb=16.8,
            unified_memory=True,
            runtimes=RuntimeAvailability(ollama=True, mlx=True),
        )

        result = recommend_models(hardware, use_case="coding", runtime="ollama", top_k=2)
        assert len(result.recommendations) == 2
        assert all(recommendation.runtime == "ollama" for recommendation in result.recommendations)

    def test_max_memory_budget_restricts_recommendations(self) -> None:
        hardware = HardwareProfile(
            platform="Darwin",
            arch="arm64",
            total_ram_gb=24.0,
            gpu_name="Apple Silicon",
            gpu_count=1,
            total_vram_gb=16.8,
            unified_memory=True,
            runtimes=RuntimeAvailability(mlx=True),
        )

        result = recommend_models(hardware, use_case="coding", max_memory_gb=6.0, top_k=5)
        assert result.recommendations
        assert all(recommendation.estimated_memory_gb <= 6.0 for recommendation in result.recommendations)

    def test_explain_excluded_returns_reasons(self) -> None:
        hardware = HardwareProfile(
            platform="Linux",
            arch="x86_64",
            total_ram_gb=4.0,
            gpu_name=None,
            gpu_count=0,
            total_vram_gb=None,
            runtimes=RuntimeAvailability(ollama=True),
        )

        result = recommend_models(hardware, use_case="coding", top_k=3, explain_excluded=True)
        assert result.excluded
        assert result.excluded[0].reason
