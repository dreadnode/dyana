from dyana.utils import count_package_prefixes, delta_fmt, sizeof_fmt


class TestSizeofFmt:
    def test_bytes(self) -> None:
        assert sizeof_fmt(0) == "0.0B"

    def test_kibibytes(self) -> None:
        assert sizeof_fmt(1024) == "1.0KiB"

    def test_mebibytes(self) -> None:
        assert sizeof_fmt(1024**2) == "1.0MiB"

    def test_gibibytes(self) -> None:
        assert sizeof_fmt(1024**3) == "1.0GiB"

    def test_tebibytes(self) -> None:
        assert sizeof_fmt(1024**4) == "1.0TiB"

    def test_negative_value(self) -> None:
        assert sizeof_fmt(-1024) == "-1.0KiB"

    def test_custom_suffix(self) -> None:
        assert sizeof_fmt(1024, suffix="iB") == "1.0KiiB"

    def test_fractional(self) -> None:
        assert sizeof_fmt(1536) == "1.5KiB"

    def test_yobibytes(self) -> None:
        result = sizeof_fmt(1024.0**8)
        assert "Yi" in result


class TestDeltaFmt:
    def test_increase(self) -> None:
        result = delta_fmt(100, 200)
        assert "200.0B" in result
        assert "red" in result

    def test_no_change(self) -> None:
        result = delta_fmt(100, 100)
        assert "100.0B" in result
        assert "red" not in result

    def test_decrease(self) -> None:
        result = delta_fmt(200, 100)
        assert "100.0B" in result
        assert "red" not in result


class TestCountPackagePrefixes:
    def test_basic(self) -> None:
        path_dict = {"os.path": "/usr/lib/os/path.py", "os.sep": "/usr/lib/os/sep.py", "sys": "/usr/lib/sys.py"}
        result = count_package_prefixes(path_dict, level=1)
        assert result == {"os": 2, "sys": 1}

    def test_level_2(self) -> None:
        path_dict = {
            "a.b.c": "x",
            "a.b.d": "y",
            "a.c.e": "z",
        }
        result = count_package_prefixes(path_dict, level=2)
        assert result == {"a.b": 2, "a.c": 1}

    def test_empty(self) -> None:
        result = count_package_prefixes({}, level=1)
        assert result == {}

    def test_single_part_below_level(self) -> None:
        path_dict = {"os": "/usr/lib/os.py"}
        result = count_package_prefixes(path_dict, level=2)
        assert result == {"os": 1}
