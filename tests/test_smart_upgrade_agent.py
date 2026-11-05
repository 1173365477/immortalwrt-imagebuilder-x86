import json
import subprocess
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schemas/system-snapshot-v1.json").read_text())


def scan(root, privacy="redacted"):
    run = subprocess.run(
        ["sh", str(ROOT / "scripts/smart-upgrade-agent.sh"), "--root", str(root), "--privacy", privacy],
        capture_output=True, text=True, check=False,
    )
    assert run.returncode == 0, run.stderr
    result = json.loads(run.stdout)
    Draft202012Validator(SCHEMA).validate(result)
    return result


def test_opkg_empty_top_level_and_sensitive_data(tmp_path):
    release = tmp_path / "etc/openwrt_release"
    release.parent.mkdir(parents=True)
    release.write_text("DISTRIB_ID='ImmortalWrt'\nDISTRIB_RELEASE='24.10.4'\nDISTRIB_TARGET='x86/64'\n")
    status = tmp_path / "usr/lib/opkg/status"
    status.parent.mkdir(parents=True)
    status.write_text(
        "Package: luci-app-openclash\nVersion: 0.48.002\nAuto-Installed: no\nDepends: bash, curl\n\n"
        "Package: dockerd\nVersion: 27.3\nAuto-Installed: yes\n\n"
        "Package: custom-unknown\nVersion: 1.0\n\n"
    )
    secret = tmp_path / "etc/config/openclash"
    secret.parent.mkdir(parents=True)
    secret.write_text("option token 'THIS_MUST_NOT_LEAK'\n")
    result = scan(tmp_path)
    assert result["system"]["package_manager"] == "opkg"
    assert len(result["packages"]["installed"]) == 3
    assert result["packages"]["top_level"] == ["luci-app-openclash"]
    assert result["packages"]["classification_status"] == "partial"
    assert result["services"]["openclash"] == "detected"
    assert result["services"]["docker"] == "detected"
    assert "THIS_MUST_NOT_LEAK" not in json.dumps(result)


def test_apk_future_release_unknown_is_not_compatible(tmp_path):
    release = tmp_path / "etc/openwrt_release"
    release.parent.mkdir(parents=True)
    release.write_text("DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='25.12.2'\n")
    apk = tmp_path / "lib/apk/db/installed"
    apk.parent.mkdir(parents=True)
    apk.write_text("P:lucky\nV:2.0\nD:libc libgcc\n\nP:unverified-thirdparty\nV:1.0\n\n")
    world = tmp_path / "etc/apk/world"
    world.parent.mkdir(parents=True, exist_ok=True)
    world.write_text("lucky\n")
    result = scan(tmp_path, "local")
    assert result["system"]["package_manager"] == "apk"
    assert result["services"]["lucky"] == "detected"
    assert result["packages"]["top_level"] == ["lucky"]
    assert {p["name"] for p in result["packages"]["installed"]} == {"lucky", "unverified-thirdparty"}
    assert result["status"] == "partial"


def test_invalid_arguments_are_rejected(tmp_path):
    result = subprocess.run(
        ["sh", str(ROOT / "scripts/smart-upgrade-agent.sh"), "--root", str(tmp_path), "--privacy", "unsafe"],
        capture_output=True, text=True,
    )
    assert result.returncode != 0

def test_docker_storage_paths_are_redacted(tmp_path):
    release = tmp_path / "etc/openwrt_release"
    release.parent.mkdir(parents=True)
    release.write_text("DISTRIB_ID='ImmortalWrt'\n")
    config = tmp_path / "etc/config/dockerd"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text("config globals 'globals'\n\toption data_root '/mnt/usb/docker'\n\toption password 'DO_NOT_COPY'\n")
    mounts = tmp_path / "proc/mounts"
    mounts.parent.mkdir(parents=True)
    mounts.write_text("/dev/sda1 /mnt/usb ext4 rw 0 0\n/dev/root / overlay rw 0 0\n")
    safe = scan(tmp_path)
    full = scan(tmp_path, "local")
    assert safe["storage"]["docker_root"] is None
    assert all(m["mountpoint"] is None for m in safe["storage"]["mounts"])
    assert full["storage"]["docker_root"] == "/mnt/usb/docker"
    assert full["storage"]["mounts"][0]["mountpoint"] == "/mnt/usb"
    assert full["storage"]["docker_root_verified"] is False
    assert "DO_NOT_COPY" not in json.dumps(safe)

def test_rom_default_and_missing_apk_world_are_not_assumed_manual(tmp_path):
    release = tmp_path / "etc/openwrt_release"
    release.parent.mkdir(parents=True)
    release.write_text("DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='25.12.2'\n")
    installed = tmp_path / "lib/apk/db/installed"
    installed.parent.mkdir(parents=True)
    installed.write_text("P:busybox\nV:1.36\n\nP:unsigned-addon\nV:1.0\n\n")
    rom = tmp_path / "rom/lib/apk/db/installed"
    rom.parent.mkdir(parents=True)
    rom.write_text("P:busybox\nV:1.36\n\n")
    report = scan(tmp_path)
    source = {pkg["name"]: pkg["source"] for pkg in report["packages"]["installed"]}
    assert source["busybox"] == "default"
    assert source["unsigned-addon"] == "unknown"
    assert report["packages"]["top_level"] == []
    assert report["packages"]["classification_status"] == "unknown"
