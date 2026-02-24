from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

from dyana.loaders.pip.main import find_site_packages, get_package_import_names


class TestFindSitePackages:
    def test_finds_site_packages(self) -> None:
        with patch.object(sys, "path", ["/usr/lib/python3.12", "/usr/lib/python3.12/site-packages"]):
            result = find_site_packages()
            assert result == "/usr/lib/python3.12/site-packages"

    def test_returns_none_when_missing(self) -> None:
        with patch.object(sys, "path", ["/usr/lib/python3.12", "/usr/local/lib"]):
            result = find_site_packages()
            assert result is None

    def test_returns_first_match(self) -> None:
        with patch.object(
            sys,
            "path",
            ["/first/site-packages", "/second/site-packages"],
        ):
            result = find_site_packages()
            assert result == "/first/site-packages"

    def test_empty_path(self) -> None:
        with patch.object(sys, "path", []):
            result = find_site_packages()
            assert result is None


class TestGetPackageImportNames:
    def test_finds_package_dir(self, tmp_path: Path) -> None:
        # Create a fake site-packages with a package directory
        site_pkg = tmp_path / "site-packages"
        site_pkg.mkdir()
        pkg_dir = site_pkg / "my_package"
        pkg_dir.mkdir()
        (pkg_dir / "__init__.py").write_text("")

        with (
            patch.object(sys, "path", [str(site_pkg)]),
            patch("dyana.loaders.pip.main.subprocess.check_output", side_effect=Exception("no pip")),
        ):
            names = get_package_import_names("my_package")
            assert "my_package" in names

    def test_finds_via_top_level_txt(self, tmp_path: Path) -> None:
        site_pkg = tmp_path / "site-packages"
        site_pkg.mkdir()
        dist_info = site_pkg / "my_pkg-1.0.0.dist-info"
        dist_info.mkdir()
        (dist_info / "top_level.txt").write_text("actual_import_name\n")

        with (
            patch.object(sys, "path", [str(site_pkg)]),
            patch("dyana.loaders.pip.main.subprocess.check_output", side_effect=Exception("no pip")),
        ):
            names = get_package_import_names("my_pkg")
            assert "actual_import_name" in names

    def test_filters_stdlib_modules(self, tmp_path: Path) -> None:
        site_pkg = tmp_path / "site-packages"
        site_pkg.mkdir()
        dist_info = site_pkg / "pkg-1.0.0.dist-info"
        dist_info.mkdir()
        (dist_info / "top_level.txt").write_text("os\nsys\nmy_real_pkg\n")

        with (
            patch.object(sys, "path", [str(site_pkg)]),
            patch("dyana.loaders.pip.main.subprocess.check_output", side_effect=Exception("no pip")),
        ):
            names = get_package_import_names("pkg")
            assert "os" not in names
            assert "sys" not in names
            assert "my_real_pkg" in names

    def test_filters_test_modules(self, tmp_path: Path) -> None:
        site_pkg = tmp_path / "site-packages"
        site_pkg.mkdir()
        dist_info = site_pkg / "pkg-1.0.0.dist-info"
        dist_info.mkdir()
        (dist_info / "top_level.txt").write_text("test\ntests\nreal_pkg\n")

        with (
            patch.object(sys, "path", [str(site_pkg)]),
            patch("dyana.loaders.pip.main.subprocess.check_output", side_effect=Exception("no pip")),
        ):
            names = get_package_import_names("pkg")
            assert "test" not in names
            assert "tests" not in names
            assert "real_pkg" in names

    def test_returns_empty_when_no_site_packages(self) -> None:
        with patch.object(sys, "path", ["/no/site-packages/here"]):
            names = get_package_import_names("anything")
            assert names == set()

    def test_hyphen_to_underscore(self, tmp_path: Path) -> None:
        site_pkg = tmp_path / "site-packages"
        site_pkg.mkdir()
        pkg_dir = site_pkg / "my_package"
        pkg_dir.mkdir()
        (pkg_dir / "__init__.py").write_text("")

        with (
            patch.object(sys, "path", [str(site_pkg)]),
            patch("dyana.loaders.pip.main.subprocess.check_output", side_effect=Exception("no pip")),
        ):
            # Input has hyphen, should find underscore version
            names = get_package_import_names("my-package")
            assert "my_package" in names
