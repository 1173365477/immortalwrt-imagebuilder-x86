from __future__ import annotations

import pytest

from resolve_version import resolve, stable_versions
from release_utils import ReleaseValidationError


INDEX = """
<a href="25.12.2/">25.12.2</a>
<a href="25.12.11/">25.12.11</a>
<a href="26.0.0-rc1/">26.0.0-rc1</a>
<a href="26.0-SNAPSHOT/">26.0-SNAPSHOT</a>
<a href="29.0.1/">29.0.1</a>
<a href="packages-29.0/">packages-29.0</a>
<a href="../">Parent</a>
"""


def test_latest_selects_numerically_highest_stable_release() -> None:
    assert stable_versions(INDEX) == ["29.0.1", "25.12.11", "25.12.2"]
    assert resolve("latest", INDEX) == "29.0.1"


def test_explicit_version_does_not_fetch_index() -> None:
    assert resolve("25.12.2") == "25.12.2"


def test_latest_rejects_empty_or_unexpected_index() -> None:
    with pytest.raises(ReleaseValidationError, match="No stable"):
        resolve("latest", '<a href="29.0-SNAPSHOT/">snapshot</a>')


def test_explicit_version_rejects_shell_text() -> None:
    with pytest.raises(ReleaseValidationError):
        resolve("latest; echo unsafe", INDEX)
