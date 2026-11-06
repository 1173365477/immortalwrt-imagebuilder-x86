#!/usr/bin/env python3
"""Fail closed before generated output is uploaded as a GitHub Artifact."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


CHUNK_BYTES = 1024 * 1024
OVERLAP_BYTES = 1024
MAX_TEXT_BYTES = 128 * 1024 * 1024
TEXT_SUFFIXES = {".json", ".md", ".txt", ".log", ".tsv", ".yml", ".yaml"}
SECRET_BYTES_RE = re.compile(
    rb"(?i)(TEST_SECRET_DO_NOT_UPLOAD_[A-Z0-9_]*|"
    rb"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    rb"(?:token|password|passwd|secret|subscription)[ \t]{0,16}[:=][^\r\n]{1,512}|"
    rb"https?://[^\s/@:]+:[^\s/@]+@)"
)
UNSAFE_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class ArtifactSafetyError(ValueError):
    def __init__(self, code: str, path: Path):
        super().__init__(code)
        self.code = code
        self.path = path


def iter_files(paths: list[Path]) -> list[Path]:
    files: set[Path] = set()
    for path in paths:
        if not path.exists():
            continue
        if path.is_symlink():
            raise ArtifactSafetyError("symlink_not_allowed", path)
        if path.is_file():
            files.add(path)
            continue
        for child in path.rglob("*"):
            if child.is_symlink():
                raise ArtifactSafetyError("symlink_not_allowed", child)
            if child.is_file() and child.name != ".gitkeep":
                files.add(child)
    return sorted(files)


def scan_bytes(path: Path) -> None:
    overlap = b""
    with path.open("rb") as stream:
        while chunk := stream.read(CHUNK_BYTES):
            window = overlap + chunk
            if SECRET_BYTES_RE.search(window):
                raise ArtifactSafetyError("sensitive_value", path)
            overlap = window[-OVERLAP_BYTES:]


def validate_text(path: Path) -> None:
    size = path.stat().st_size
    if size > MAX_TEXT_BYTES:
        raise ArtifactSafetyError("text_file_too_large", path)
    try:
        text = path.read_text(encoding="utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ArtifactSafetyError("invalid_utf8", path) from exc
    if UNSAFE_CONTROL_RE.search(text):
        raise ArtifactSafetyError("control_character", path)
    if path.suffix.lower() == ".json":
        try:
            json.loads(text)
        except json.JSONDecodeError as exc:
            raise ArtifactSafetyError("invalid_json", path) from exc


def validate(paths: list[Path]) -> int:
    files = iter_files(paths)
    if not files:
        raise ArtifactSafetyError("no_artifact_files", Path("generated"))
    for path in files:
        scan_bytes(path)
        if path.suffix.lower() in TEXT_SUFFIXES:
            validate_text(path)
    return len(files)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", action="append", type=Path, required=True)
    args = parser.parse_args()
    try:
        count = validate(args.path)
    except (ArtifactSafetyError, OSError) as exc:
        code = exc.code if isinstance(exc, ArtifactSafetyError) else "read_error"
        path = exc.path if isinstance(exc, ArtifactSafetyError) else Path("generated")
        print(f"::error title=ARTIFACT_SAFETY::{code}: {path.as_posix()}")
        return 1
    print(f"Artifact safety validation passed for {count} file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
