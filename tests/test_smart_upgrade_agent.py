import json
import shutil
import subprocess
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schemas/system-snapshot-v1.json").read_text())


def scan(root, privacy="redacted", fixture_dir=None):
    command = ["sh", str(ROOT / "scripts/smart-upgrade-agent.sh"), "--root", str(root), "--privacy", privacy]
    if fixture_dir:
        command += ["--fixture-dir", str(fixture_dir)]
    run = subprocess.run(
        command,
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
    assert result["services"]["openclash"]["package_detected"] is True
    assert result["services"]["openclash"]["running"] == "unknown"
    assert result["services"]["docker"]["package_detected"] is True
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
    assert result["services"]["lucky"]["package_detected"] is True
    # APK world is an intent candidate, not proof of manual installation.
    assert result["packages"]["top_level"] == []
    assert result["packages"]["intent_candidates"] == ["lucky"]
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
    mounts = tmp_path / "proc/self/mountinfo"
    mounts.parent.mkdir(parents=True)
    mounts.write_text("24 1 8:1 / /mnt/usb rw - ext4 /dev/sda1 rw\n25 1 0:1 / / rw - overlay overlay rw\n")
    safe = scan(tmp_path)
    full = scan(tmp_path, "local")
    assert safe["storage"]["docker"]["root"] is None
    assert all(m["mountpoint"] is None for m in safe["storage"]["mount_inventory"]["entries"])
    assert full["storage"]["docker"]["root"] == "/mnt/usb/docker"
    assert full["storage"]["mount_inventory"]["entries"][0]["mountpoint"] == "/mnt/usb"
    assert full["storage"]["docker"]["verified"] is False
    assert full["storage"]["targets"][0]["risk"] == "external_persistent"
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
    packages = {pkg["name"]: pkg for pkg in report["packages"]["installed"]}
    assert packages["busybox"]["origin"] == "official"
    assert packages["busybox"]["install_reason"] == "system_default"
    assert packages["unsigned-addon"]["origin"] == "unknown"
    assert report["packages"]["top_level"] == []
    assert report["packages"]["classification_status"] == "unknown"

def test_missing_package_database_does_not_report_service_absence(tmp_path):
    report = scan(tmp_path)
    assert report["system"]["package_manager"] == "unknown"
    assert report["services"]["docker"]["package_detected"] is None
    assert any("package database unavailable" in w for w in report["warnings"])


def _storage_fixture(tmp_path, docker_root="/var/lib/docker", config_root=None, mounts="", docker_mounts=""):
    (tmp_path / "etc").mkdir(parents=True, exist_ok=True)
    (tmp_path / "etc/openwrt_release").write_text("DISTRIB_ID='ImmortalWrt'\n")
    mountinfo = tmp_path / "proc/self/mountinfo"
    mountinfo.parent.mkdir(parents=True)
    mountinfo.write_text(mounts or "25 1 0:1 / / rw - overlay overlay rw\n")
    if config_root:
        config = tmp_path / "etc/config/dockerd"
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text(f"option data_root '{config_root}'\n")
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    (fixture / "docker-info.txt").write_text(docker_root + "\n")
    if docker_mounts:
        (fixture / "docker-mounts.tsv").write_text(docker_mounts)
    return fixture


def test_runtime_docker_root_wins_and_records_config_mismatch(tmp_path):
    fixture = _storage_fixture(tmp_path, "/data/docker", "/var/lib/docker", "25 1 0:1 / / rw - overlay overlay rw\n26 1 8:2 / /data rw - ext4 /dev/sdb2 rw\n")
    report = scan(tmp_path, "local", fixture)
    assert report["storage"]["docker"]["root"] == "/data/docker"
    assert report["storage"]["docker"]["verified"] is True
    assert report["storage"]["docker"]["config_mismatch"] is True
    assert report["storage"]["targets"][0]["risk"] == "external_persistent"


def test_root_volume_and_external_bind_are_independently_classified(tmp_path):
    fixture = _storage_fixture(
        tmp_path,
        mounts="25 1 0:1 / / rw - overlay overlay rw\n26 1 8:2 / /data rw - ext4 /dev/sdb2 rw\n",
        docker_mounts="volume\t/var/lib/docker/volumes/a/_data\t/app\ta\nbind\t/data/media\t/media\t\n",
    )
    report = scan(tmp_path, "local", fixture)
    risks = {(item["kind"], item["risk"]) for item in report["storage"]["targets"]}
    assert ("docker_root", "rootfs_or_overlay") in risks
    assert ("volume", "rootfs_or_overlay") in risks
    assert ("bind", "external_persistent") in risks


def test_longest_nested_mount_and_symlink_are_resolved(tmp_path):
    (tmp_path / "data/docker-real").mkdir(parents=True)
    (tmp_path / "docker-link").symlink_to(tmp_path / "data/docker-real")
    fixture = _storage_fixture(
        tmp_path,
        docker_root="/docker-link",
        mounts="25 1 0:1 / / rw - overlay overlay rw\n26 1 8:2 / /data rw - ext4 /dev/sdb2 rw\n27 26 8:3 / /data/docker-real rw - xfs /dev/sdc3 rw\n",
    )
    report = scan(tmp_path, "local", fixture)
    target = report["storage"]["targets"][0]
    assert target["source"] == "/data/docker-real"
    assert target["mount_id"] == "mount-3"


def test_daemon_permission_and_truncated_mounts_are_unknown(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/openwrt_release").write_text("DISTRIB_ID='ImmortalWrt'\n")
    mountinfo = tmp_path / "proc/self/mountinfo"
    mountinfo.parent.mkdir(parents=True)
    mountinfo.write_text("".join(f"{i+20} 1 0:1 / /m{i} rw - tmpfs tmpfs rw\n" for i in range(260)))
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    (fixture / "docker-info.denied").write_text("")
    report = scan(tmp_path, "local", fixture)
    assert report["storage"]["docker"]["daemon_state"] == "permission_denied"
    assert report["storage"]["mount_inventory"]["truncated"] is True
    assert report["storage"]["status"] == "partial"
    assert "mountinfo_truncated" in report["storage"]["errors"]


def test_service_package_definition_and_runtime_are_distinct(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/openwrt_release").write_text("DISTRIB_ID='ImmortalWrt'\n")
    status = tmp_path / "usr/lib/opkg/status"
    status.parent.mkdir(parents=True)
    status.write_text("Package: lucky\nVersion: 1\nStatus: install ok installed\n\n")
    init = tmp_path / "etc/init.d/lucky"
    init.parent.mkdir(parents=True)
    init.write_text("#!/bin/sh\n")
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    (fixture / "service-status.tsv").write_text("lucky\tstopped\n")
    report = scan(tmp_path, fixture_dir=fixture)
    lucky = report["services"]["lucky"]
    assert lucky == {"package_detected": True, "executable_exists": False, "service_definition_exists": True, "running": "stopped"}


def test_identity_uses_injected_read_only_evidence(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/openwrt_release").write_text("DISTRIB_ID='ImmortalWrt'\nDISTRIB_TARGET='x86/64'\nDISTRIB_ARCH='x86_64'\nDISTRIB_IMAGE_TYPE='combined-efi'\n")
    mountinfo = tmp_path / "proc/self/mountinfo"
    mountinfo.parent.mkdir(parents=True)
    mountinfo.write_text("25 1 0:1 / / rw - overlay overlay rw\n")
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    (fixture / "uname.txt").write_text("x86_64\n")
    (fixture / "package-arch.txt").write_text("x86_64\n")
    (fixture / "boot-mode.txt").write_text("efi\n")
    (fixture / "ubus-system-board.json").write_text('{"board_name":"generic"}\n')
    report = scan(tmp_path, "local", fixture)
    assert report["system"]["boot_mode"] == "efi"
    assert report["system"]["profile"] == "generic"
    assert report["system"]["rootfs_type"] == "overlay"
    assert report["system"]["firmware_image_type"] == "combined-efi"
    assert report["system"]["identity_status"] == "consistent"


def test_identity_conflict_is_explicit(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/openwrt_release").write_text("DISTRIB_ID='ImmortalWrt'\nDISTRIB_TARGET='x86/64'\nDISTRIB_ARCH='x86_64'\n")
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    (fixture / "uname.txt").write_text("aarch64\n")
    (fixture / "package-arch.txt").write_text("aarch64_cortex-a53\n")
    report = scan(tmp_path, fixture_dir=fixture)
    assert report["system"]["identity_status"] == "conflict"
    assert set(report["system"]["identity_errors"]) == {"target_uname_arch_mismatch", "release_package_arch_mismatch"}


def test_realistic_apk_v3_database_keeps_constraints_and_virtual_relations(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/openwrt_release").write_text("DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='25.12.2'\n")
    installed = tmp_path / "lib/apk/db/installed"
    installed.parent.mkdir(parents=True)
    shutil.copyfile(ROOT / "tests/fixtures/apk-v3-installed.txt", installed)
    report = scan(tmp_path, "local")
    app = next(item for item in report["packages"]["installed"] if item["name"] == "luci-app-example")
    assert app["dependencies_raw"] == "libc>=1.2.5-r0 so:libubus.so.20250102 virtual:rpc-provider"
    assert [(item["relation"], item["name"]) for item in app["depends"]] == [
        ("package", "libc"), ("soname", "libubus.so.20250102"), ("virtual", "rpc-provider")
    ]
    assert app["depends"][0]["operator"] == ">="
    assert app["depends"][0]["version"] == "1.2.5-r0"
    assert app["provides_raw"] == "virtual:luci-app-example=2.0.0-r1"


def test_realistic_opkg_status_excludes_removed_and_preserves_auto_reason(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/openwrt_release").write_text("DISTRIB_ID='ImmortalWrt'\n")
    status = tmp_path / "usr/lib/opkg/status"
    status.parent.mkdir(parents=True)
    shutil.copyfile(ROOT / "tests/fixtures/opkg-status-realistic.txt", status)
    report = scan(tmp_path, "local")
    packages = {item["name"]: item for item in report["packages"]["installed"]}
    assert set(packages) == {"busybox", "libubox20240329"}
    assert packages["busybox"]["install_reason"] == "manual"
    assert packages["libubox20240329"]["install_reason"] == "dependency"
