"""Out-of-band target verification and a private, atomically published catalog."""

from __future__ import annotations

import fcntl
import json
import multiprocessing
import os
import re
import secrets
import stat
import tempfile
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from scripts.migration_plan import canonical_digest
from scripts.release_resolver import ReleaseRequest, resolve_release

POLICY = ReleaseRequest()
DEFAULT_TTL = 3600
MAX_BYTES = 64 * 1024 * 1024
REF_PATTERN = re.compile(r"[a-f0-9]{48}")
SHA_PATTERN = re.compile(r"[a-f0-9]{64}")
HOST = "downloads.immortalwrt.org"
PREFIX = f"/releases/{POLICY.version}/"
BASE = f"https://{HOST}{PREFIX}targets/{POLICY.target}"
IMAGE = (f"{POLICY.distribution}-{POLICY.version}-{POLICY.target.replace('/', '-')}-"
         f"{POLICY.profile}-{POLICY.filesystem}-{POLICY.image_type}.img.gz")
TARGET_KEYS = {
    "distribution": POLICY.distribution, "target_version": POLICY.version,
    "target": POLICY.target, "profile": POLICY.profile, "filesystem": POLICY.filesystem,
    "image_type": POLICY.image_type, "arch": POLICY.architecture,
}
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK


def strict_json(raw: bytes):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def invalid_constant(_value):
        raise ValueError("invalid JSON constant")

    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=invalid_constant)


def private_file(path: Path, limit: int) -> bytes:
    with os.fdopen(os.open(path, FILE_FLAGS), "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_size > limit):
            raise ValueError("invalid private file")
        data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError("private file exceeds limit")
        return data


def verify_url(url: str) -> None:
    parts = urlsplit(url)
    if (parts.scheme != "https" or parts.netloc != HOST or parts.query or parts.fragment
            or url != f"https://{HOST}{parts.path}" or not parts.path.startswith(PREFIX)):
        raise ValueError("non-official release URL")
    relative = parts.path[len(PREFIX):]
    roots = (f"targets/{POLICY.target}/", f"packages/{POLICY.architecture}/")
    if (not relative.startswith(roots)
            or not all(re.fullmatch(r"[A-Za-z0-9_+.\-]+", item)
                       and item not in (".", "..") for item in relative.split("/"))):
        raise ValueError("invalid release resource path")


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class OfficialTransport:
    def __init__(self):
        self.remaining = MAX_BYTES
        self.requests = 0
        self.cache: dict[str, bytes] = {}
        self.opener = build_opener(ProxyHandler({}), NoRedirects())

    def resource(self, url: str, method: str):
        for _ in range(4):
            verify_url(url)
            self.requests += 1
            if self.requests > 64:
                raise ValueError("too many release resources")
            try:
                return self.opener.open(Request(url, method=method), timeout=8)
            except HTTPError as exc:
                with exc:
                    location = exc.headers.get("Location")
                    if exc.code not in (301, 302, 303, 307, 308) or not location:
                        raise ValueError("official release resource is unavailable") from None
                    url = urljoin(url, location)
        raise ValueError("too many release redirects")

    def fetch(self, url: str) -> bytes:
        if url not in self.cache:
            with self.resource(url, "GET") as response:
                verify_url(response.url)
                data = response.read(self.remaining + 1)
                self.remaining -= len(data)
                if self.remaining < 0:
                    raise ValueError("release metadata exceeds byte budget")
                self.cache[url] = data
        return self.cache[url]

    def check_artifact(self, url: str) -> None:
        with self.resource(url, "HEAD") as response:
            verify_url(response.url)
            if response.status != 200 or int(response.headers.get("Content-Length", "0")) <= 0:
                raise ValueError("official artifact availability could not be verified")


def resolve_catalog_entry(fetch, check_artifact, ttl: int) -> dict:
    def read_official(url):
        verify_url(url)
        raw = fetch(url)
        if url == BASE + "/profiles.json":
            profiles = strict_json(raw)
            if (not isinstance(profiles, dict) or profiles.get("version_number") != POLICY.version
                    or profiles.get("arch_packages") != POLICY.architecture):
                raise ValueError("unexpected official profiles identity")
        return raw

    capabilities, packages = resolve_release(POLICY, fetch=read_official)
    if capabilities.get("expected_image_name") != IMAGE:
        raise ValueError("unexpected official image identity")
    check_artifact(f"{BASE}/{IMAGE}")
    check_artifact(capabilities["imagebuilder_url"])
    now = int(time.time())
    entry = {
        "target_ref": secrets.token_hex(24), "verified_at": now, "expires_at": now + ttl,
        "capabilities": capabilities, "packages": packages,
    }
    return {**entry, "entry_digest": canonical_digest(entry)}


def _refresh_worker(path: Path, ttl: int) -> None:
    try:
        transport = OfficialTransport()
        entry = resolve_catalog_entry(transport.fetch, transport.check_artifact, ttl)
        with path.open("wb") as output:
            encoded = json.dumps(entry, separators=(",", ":")).encode()
            if len(encoded) > MAX_BYTES:
                raise ValueError("catalog exceeds size limit")
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        raise SystemExit(1) from None


def refresh_catalog(path: Path, *, ttl: int = DEFAULT_TTL, timeout: int = 90) -> None:
    if ttl <= 0 or timeout <= 0:
        raise ValueError("invalid catalog limits")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = path.parent.stat(follow_symlinks=False)
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid()
            or parent.st_mode & 0o022):
        raise ValueError("invalid catalog directory")
    lock_path = path.with_suffix(path.suffix + ".lock")
    with os.fdopen(os.open(lock_path, os.O_CREAT | os.O_NOFOLLOW | os.O_RDWR | os.O_NONBLOCK,
                          0o600), "r+b") as lock:
        if not stat.S_ISREG(os.fstat(lock.fileno()).st_mode):
            raise ValueError("invalid refresh lock")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fd, temporary = tempfile.mkstemp(prefix=".catalog-", dir=path.parent)
        os.close(fd)
        staging = Path(temporary)
        try:
            worker = multiprocessing.get_context("spawn").Process(
                target=_refresh_worker, args=(staging, ttl), daemon=True
            )
            worker.start()
            worker.join(timeout)
            if worker.is_alive():
                worker.kill()
                worker.join()
            if worker.exitcode != 0:
                raise ValueError("official target refresh failed")
            load_catalog(staging)
            staging.replace(path)
        finally:
            staging.unlink(missing_ok=True)


def load_catalog(path: Path) -> dict:
    entry = strict_json(private_file(path, MAX_BYTES))
    if not isinstance(entry, dict) or set(entry) != {
        "target_ref", "verified_at", "expires_at", "capabilities", "packages", "entry_digest"
    }:
        raise ValueError("invalid catalog")
    unsigned = {key: value for key, value in entry.items() if key != "entry_digest"}
    caps = entry["capabilities"]
    index = entry["packages"]
    if (not isinstance(caps, dict) or not isinstance(index, dict) or not index
            or not isinstance(entry["target_ref"], str) or not REF_PATTERN.fullmatch(entry["target_ref"])
            or type(entry["verified_at"]) is not int or type(entry["expires_at"]) is not int
            or not 0 < entry["verified_at"] < entry["expires_at"]
            or entry["verified_at"] > int(time.time())
            or any(caps.get(key) != value for key, value in TARGET_KEYS.items())
            or caps.get("channel") != "release" or caps.get("support_status") != "supported"
            or caps.get("expected_image_name") != IMAGE
            or caps.get("package_manager") not in ("apk", "opkg")
            or canonical_digest(unsigned) != entry["entry_digest"]
            or canonical_digest(index) != caps.get("official_index_digest")
            or canonical_digest({key: value for key, value in caps.items()
                                 if key != "resolution_digest"}) != caps.get("resolution_digest")):
        raise ValueError("invalid catalog evidence")
    return entry


def public_target(entry: dict) -> dict:
    caps = entry["capabilities"]
    return {
        **{key: entry[key] for key in ("target_ref", "verified_at", "expires_at")},
        **{key: caps[key] for key in ("distribution", "target", "profile", "filesystem",
                                      "image_type", "package_manager", "resolution_digest")},
        "version": caps["target_version"], "architecture": caps["arch"],
    }
