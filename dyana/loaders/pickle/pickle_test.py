from __future__ import annotations

from dyana.loaders.pickle.main import inspect_object


class _FakeModel:
    def __init__(self) -> None:
        self.weight = [1.0, 2.0]
        self.bias = [0.1]


class _FakeArrayLike:
    def __init__(self) -> None:
        self.shape = (3, 4)

    def __len__(self) -> int:
        return 12


class TestInspectObject:
    def test_dict(self) -> None:
        result = inspect_object({"a": 1, "b": 2})
        assert "dict" in result["object_type"]
        assert result["length"] == 2

    def test_list(self) -> None:
        result = inspect_object([1, 2, 3])
        assert "list" in result["object_type"]
        assert result["length"] == 3

    def test_string(self) -> None:
        result = inspect_object("hello")
        assert "str" in result["object_type"]
        assert result["length"] == 5

    def test_integer(self) -> None:
        result = inspect_object(42)
        assert "int" in result["object_type"]
        assert "length" not in result

    def test_object_with_dict(self) -> None:
        obj = _FakeModel()
        result = inspect_object(obj)
        assert "object_attributes" in result
        assert "weight" in result["object_attributes"]
        assert "bias" in result["object_attributes"]

    def test_object_with_shape(self) -> None:
        obj = _FakeArrayLike()
        result = inspect_object(obj)
        assert result["shape"] == "(3, 4)"
        assert result["length"] == 12

    def test_none(self) -> None:
        result = inspect_object(None)
        assert "NoneType" in result["object_type"]
        assert "length" not in result

    def test_tuple(self) -> None:
        result = inspect_object((1, 2, 3))
        assert "tuple" in result["object_type"]
        assert result["length"] == 3

    def test_nested_dict(self) -> None:
        result = inspect_object({"state_dict": {"layer.weight": [1.0]}, "epoch": 5})
        assert result["length"] == 2

    def test_empty_dict(self) -> None:
        result = inspect_object({})
        assert result["length"] == 0

    def test_set(self) -> None:
        result = inspect_object({1, 2, 3})
        assert "set" in result["object_type"]
        assert result["length"] == 3
