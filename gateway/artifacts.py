"""Bounded ZIP and internal provenance verification."""

from __future__ import annotations

import hashlib
import io
import json
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from jsonschema import Draft202012Validator

from .database import DispatchIntent, TaskRecord
from .errors import ErrorCode, GatewayError
from .github import ArtifactDownload


@dataclass(frozen=True)
class ArtifactLimits:
    archive_bytes: int = 256 * 1024 * 1024
    expanded_bytes: int = 1024 * 1024 * 1024
    members: int = 256
    compression_ratio: int = 200


def _canonical_digest(value: dict[str, object]) -> str:
    copy = dict(value)
    copy["provenance_id"] = ""
    copy["digest"] = ""
    encoded = json.dumps(copy, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def verify_artifact_zip(download: ArtifactDownload, task: TaskRecord, intent: DispatchIntent,
                        *, limits: ArtifactLimits = ArtifactLimits()) -> dict[str, object]:
    try:
        if (download.expired or download.repository != task.repository
                or download.run_id != intent.github_run_id
                or download.run_attempt != intent.github_run_attempt):
            raise ValueError("artifact identity")
        data = download.data
        if not data or len(data) > limits.archive_bytes:
            raise ValueError("archive size")
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if not infos or len(infos) > limits.members:
                raise ValueError("member count")
            names: set[str] = set()
            total = 0
            files: dict[str, bytes] = {}
            for info in infos:
                path = PurePosixPath(info.filename)
                if (path.is_absolute() or ".." in path.parts or not path.parts
                        or info.filename in names or "\\" in info.filename):
                    raise ValueError("unsafe or duplicate path")
                names.add(info.filename)
                mode = info.external_attr >> 16
                kind = stat.S_IFMT(mode)
                if stat.S_ISLNK(mode) or kind not in {0, stat.S_IFREG, stat.S_IFDIR}:
                    raise ValueError("unsafe member type")
                if info.is_dir():
                    continue
                total += info.file_size
                if total > limits.expanded_bytes:
                    raise ValueError("expanded size")
                if info.compress_size == 0 and info.file_size > 0:
                    raise ValueError("compression ratio")
                if info.compress_size and info.file_size / info.compress_size > limits.compression_ratio:
                    raise ValueError("compression ratio")
                files[info.filename] = archive.read(info)
        provenance_names = [name for name in files if PurePosixPath(name).name == "build-provenance-v2.json"]
        if len(provenance_names) != 1:
            raise ValueError("provenance count")
        provenance = json.loads(files[provenance_names[0]])
        if not isinstance(provenance, dict) or provenance.get("schema_version") != "2.0.0":
            raise ValueError("provenance schema")
        schema_path = Path(__file__).resolve().parents[1] / "schemas/build-provenance-v2.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        errors = list(Draft202012Validator(schema).iter_errors(provenance))
        if errors:
            raise ValueError("provenance schema")
        digest = _canonical_digest(provenance)
        if provenance.get("digest") != digest or provenance.get("provenance_id") != f"urn:sha256:{digest}":
            raise ValueError("provenance digest")
        trace = provenance.get("trace")
        artifact = provenance.get("artifact")
        if not isinstance(trace, dict) or not isinstance(artifact, dict):
            raise ValueError("provenance fields")
        expected_trace = {
            "repository": task.repository,
            "trusted_code_commit_sha": intent.trusted_code_commit_sha,
            "evidence_commit_sha": intent.evidence_commit_sha,
            "workflow_runtime_sha": intent.expected_runtime_sha,
            "workflow_run_id": intent.github_run_id,
            "workflow_run_attempt": intent.github_run_attempt,
        }
        if any(trace.get(key) != value for key, value in expected_trace.items()):
            raise ValueError("trace identity")
        if (provenance.get("request_id") != task.request_id
                or provenance.get("build_input_id") != task.build_input_id
                or provenance.get("build_input_digest") != task.build_input_digest
                or provenance.get("snapshot_digest") != intent.snapshot_digest
                or provenance.get("plan_digest") != intent.plan_digest
                or provenance.get("flash_ready") is not False
                or provenance.get("build_allowed") is not True):
            raise ValueError("build identity")
        filename = artifact.get("filename")
        matches = [name for name in files if PurePosixPath(name).name == filename]
        if not isinstance(filename, str) or len(matches) != 1:
            raise ValueError("firmware count")
        firmware = files[matches[0]]
        actual_sha = hashlib.sha256(firmware).hexdigest()
        if artifact.get("sha256") != actual_sha or artifact.get("size_bytes") != len(firmware):
            raise ValueError("firmware bytes")
        return {
            "request_id": task.request_id, "filename": filename, "sha256": actual_sha,
            "size_bytes": len(firmware), "github_run_id": intent.github_run_id,
            "github_run_attempt": intent.github_run_attempt, "verified": True,
            "flash_ready": False,
        }
    except (OSError, ValueError, KeyError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        raise GatewayError(
            ErrorCode.ARTIFACT_UNVERIFIED, 409, internal_detail=type(exc).__name__
        ) from exc

