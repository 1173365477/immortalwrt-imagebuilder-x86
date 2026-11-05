from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def load_hyphenated(alias: str, filename: str) -> None:
    spec = importlib.util.spec_from_file_location(alias, SCRIPTS / filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[alias] = module
    spec.loader.exec_module(module)


load_hyphenated("parse_owut_report", "parse-owut-report.py")
load_hyphenated("validate_manifest", "validate-manifest.py")

