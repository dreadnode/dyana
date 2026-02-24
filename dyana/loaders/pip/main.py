import argparse
import glob
import importlib
import os
import re
import subprocess
import sys

from dyana import Profiler  # type: ignore[attr-defined]


def find_site_packages() -> str | None:
    """Find the site-packages directory where pip installs packages."""
    for path in sys.path:
        if path.endswith("site-packages"):
            return path
    return None


def get_package_import_names(package_name: str) -> set[str]:
    """Get possible import names for a package using various methods."""
    importlib.invalidate_caches()

    site_packages = find_site_packages()
    if not site_packages:
        return set()

    # look for package name variations
    base_name = package_name.replace("-", "_")
    variations = [package_name, base_name, base_name.lower()]

    try:
        # some packages have a different casing ( upfilelive -> UpFileLive ) and the simplest
        # way to find the correct name is to use the pip show command
        pip_name = (
            subprocess.check_output(f"{sys.executable} -m pip show {package_name} | grep Name", shell=True, text=True)
            .split(":")[1]
            .strip()
        )
        variations.append(pip_name)
    except Exception:
        pass

    import_names = set()
    for variant in set(variations):
        # Only look in site-packages directory
        package_path = os.path.join(site_packages, variant)
        if os.path.exists(package_path):
            if os.path.isfile(package_path + ".py"):
                import_names.add(variant)
            elif os.path.isdir(package_path) and os.path.exists(os.path.join(package_path, "__init__.py")):
                import_names.add(variant)

        # check dist-info directory for this specific variant
        dist_info_pattern = os.path.join(site_packages, f"{variant}*.dist-info")
        for dist_info_dir in glob.glob(dist_info_pattern):
            # try top_level.txt
            top_level = os.path.join(dist_info_dir, "top_level.txt")
            if os.path.exists(top_level):
                with open(top_level) as f:
                    for name in f.readlines():
                        name = name.strip()
                        if name and name not in sys.stdlib_module_names and name != "test" and name != "tests":
                            import_names.add(name)

    return import_names


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Install a Python package via PIP")
    parser.add_argument("--package", help="PIP compatible package name or expression", required=True)
    args = parser.parse_args()
    profiler: Profiler = Profiler()

    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--no-cache-dir", "--root-user-action=ignore", args.package]
        )
        profiler.on_stage("after_installation")

        # get base package name (remove version, etc)
        package_name = re.split("[^a-zA-Z0-9_-]", args.package)[0]
        normalized_name = package_name.strip().lower().replace("-", "_")
        import_success = False

        # first attempt to import directly
        for name in {package_name, normalized_name}:
            try:
                importlib.import_module(normalized_name)
                import_success = True
                print(f"imported as {name}")
                break
            except ImportError as _:
                pass

        if not import_success:
            import_names = get_package_import_names(package_name)
            for name in sorted(import_names, key=len):
                try:
                    importlib.import_module(name)
                    import_success = True
                    print(f"imported as {name}")
                    break
                except ImportError as _:
                    pass

        if not import_success:
            profiler.track_warning("pip", "could not find import name for package")
        else:
            profiler.on_stage("after_import")

    except Exception as e:
        profiler.track_error("pip", str(e))
