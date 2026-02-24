from __future__ import annotations

import argparse
import os
import pickle
import subprocess
import sys
import typing as t


def inspect_object(data: t.Any) -> dict[str, t.Any]:
    """Inspect a deserialized object and return its properties."""
    result: dict[str, t.Any] = {
        "object_type": str(type(data)),
    }

    if hasattr(data, "__dict__"):
        result["object_attributes"] = list(data.__dict__.keys())

    if hasattr(data, "shape"):
        result["shape"] = str(data.shape)

    if hasattr(data, "__len__"):
        try:
            result["length"] = len(data)
        except Exception:
            pass

    return result


if __name__ == "__main__":
    from dyana import Profiler  # type: ignore[attr-defined]

    parser = argparse.ArgumentParser(description="Run a Python pickle file")
    parser.add_argument("--pickle", help="Path to pickle file", required=True)
    parser.add_argument("--extra-requirements", help="Extra pip requirements", default="")
    args = parser.parse_args()
    profiler: Profiler = Profiler(gpu=True)

    # Install any extra dependencies requested
    if args.extra_requirements:
        try:
            print(f"Installing runtime dependencies: {args.extra_requirements}")
            requirements = args.extra_requirements.split(",")
            for req in requirements:
                req = req.strip()
                if req:
                    print(f"Installing dependency: {req}")
                    result = subprocess.run(
                        [sys.executable, "-m", "pip", "install", "--no-cache-dir", req],
                        capture_output=True,
                        text=True,
                    )
                    if result.returncode != 0:
                        profiler.track_warning("dependencies", f"Failed to install {req}: {result.stderr}")
                        print(f"Warning: Failed to install {req}: {result.stderr}")
                    else:
                        print(f"Successfully installed {req}")
        except Exception as e:
            profiler.track_error("dependencies", f"Failed to install dependencies: {str(e)}")
            print(f"Error installing dependencies: {str(e)}")

    if not os.path.exists(args.pickle):
        profiler.track_error("pickle", "Pickle file not found")
    else:
        try:
            with open(args.pickle, "rb") as f:
                data = pickle.load(f)
                profiler.on_stage("after_load")

                info = inspect_object(data)
                for key, value in info.items():
                    profiler.track_extra(key, value)
        except ImportError as e:
            profiler.track_error("pickle", str(e))
        except Exception as e:
            profiler.track_error("pickle", str(e))
