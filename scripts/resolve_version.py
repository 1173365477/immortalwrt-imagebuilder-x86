#!/usr/bin/env python3
"""Resolve 'latest' to the newest published stable ImmortalWrt release.

The official releases/ directory is the source of version candidates; the
existing manifest validator checks that its artifacts are actually usable.
"""
from __future__ import annotations

import argparse
import re
from html.parser import HTMLParser
from pathlib import Path

from release_utils import ReleaseValidationError, get_url, official_download_root, parse_version

STABLE_VERSION = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")


class DirectoryLinks(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            self.links.extend(value for name, value in attrs if name == "href" and value is not None)


def stable_versions(index_html: str) -> list[str]:
    parser = DirectoryLinks()
    parser.feed(index_html)
    candidates = set()
    for href in parser.links:
        # Accept only direct child release directories, never snapshot/RC/beta.
        name = href.removesuffix("/")
        if href.endswith("/") and STABLE_VERSION.fullmatch(name):
            candidates.add(name)
    return sorted(candidates, key=lambda v: (parse_version(v).major, parse_version(v).minor, parse_version(v).patch or 0), reverse=True)


def resolve(request: str, index_html: str | None = None, *, distribution: str = "immortalwrt") -> str:
    if request != "latest":
        return parse_version(request).target_version
    if index_html is None:
        index_html = get_url(f"{official_download_root(distribution)}/releases/").decode("utf-8")
    candidates = stable_versions(index_html)
    if not candidates:
        raise ReleaseValidationError("No stable ImmortalWrt release directories found in the official index.")
    return candidates[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", default="latest")
    parser.add_argument("--distribution", choices=("immortalwrt", "openwrt"), default="immortalwrt")
    parser.add_argument("--output", type=Path, default=Path("generated/resolved-version.txt"))
    args = parser.parse_args()
    try:
        version = resolve(args.version, distribution=args.distribution)
    except (ReleaseValidationError, UnicodeDecodeError) as exc:
        parser.exit(2, f"::error::{exc}\n")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(version + "\n", encoding="utf-8")
    print(f"Selected ImmortalWrt release: {version} (requested: {args.version})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
