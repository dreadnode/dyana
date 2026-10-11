from __future__ import annotations

import json
from importlib.resources import files
from typing import Any, cast

from dyana.fit.models import FitCatalog


def _read_catalog_file(name: str) -> list[dict[str, Any]]:
    resource = files("dyana.data").joinpath(name)
    return cast(list[dict[str, Any]], json.loads(resource.read_text()))


def load_catalog() -> FitCatalog:
    providers = _read_catalog_file("providers.json")
    models = _read_catalog_file("models.json")
    return FitCatalog.model_validate({"providers": providers, "models": models})
