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


def _sysfs_block(root, major_minor, name, *, disk=None, partition=None, virtual=False):
    if virtual:
        node = root / "sys/devices/virtual/block" / name
    else:
        disk = disk or name
        node = root / "sys/devices/pci0000:00/block" / disk
        if name != disk:
            node = node / name
    node.mkdir(parents=True, exist_ok=True)
    (node / "dev").write_text(major_minor + "\n")
    (node / "size").write_text("2048\n")
    if partition is not None:
        (node / "partition").write_text(str(partition) + "\n")
    dev_link = root / "sys/dev/block" / major_minor
    dev_link.parent.mkdir(parents=True, exist_ok=True)
    dev_link.symlink_to(node)
    return node


def _sysfs_slave(parent, slave):
    slaves = parent / "slaves"
    slaves.mkdir(exist_ok=True)
    (slaves / slave.name).symlink_to(slave)


def _topology_fixture(tmp_path, mounts, docker_root="/data/docker", docker_mounts=""):
    fixture = _storage_fixture(
        tmp_path,
        docker_root=docker_root,
        mounts=mounts,
        docker_mounts=docker_mounts,
    )
    (fixture / "docker-container-mounts.tsv").write_text(docker_mounts)
    (fixture / "docker-volumes.tsv").write_text("")
    return fixture


def test_runtime_docker_root_wins_and_records_config_mismatch(tmp_path):
    fixture = _storage_fixture(tmp_path, "/data/docker", "/var/lib/docker", "25 1 0:1 / / rw - overlay overlay rw\n26 1 8:2 / /data rw - ext4 /dev/sdb2 rw\n")
    (fixture / "block-topology.tsv").write_text("8:2\tsdb\t2\tcomplete\n")
    sys_size = tmp_path / "sys/dev/block/8:2/size"
    sys_size.parent.mkdir(parents=True)
    sys_size.write_text("2097152\n")
    report = scan(tmp_path, "local", fixture)
    assert report["storage"]["docker"]["root"] == "/data/docker"
    assert report["storage"]["docker"]["verified"] is True
    assert report["storage"]["docker"]["config_mismatch"] is True
    assert report["storage"]["targets"][0]["risk"] == "external_persistent"
    data_mount = report["storage"]["mount_inventory"]["entries"][1]
    assert data_mount["block_resolution"] == "resolved"
    assert data_mount["size_bytes"] == 1073741824


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


def test_third_party_origin_requires_read_only_rom_manifest_evidence(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/openwrt_release").write_text("DISTRIB_ID='OpenWrt'\n")
    installed = tmp_path / "lib/apk/db/installed"
    installed.parent.mkdir(parents=True)
    installed.write_text("P:vendor-addon\nV:1.0\n\nP:unproven-addon\nV:1.0\n\n")
    origins = tmp_path / "rom/usr/share/smart-upgrade/package-origins.tsv"
    origins.parent.mkdir(parents=True)
    origins.write_text(f"vendor-addon\tthird_party\t{'a' * 64}\n")
    report = scan(tmp_path, "local")
    packages = {item["name"]: item for item in report["packages"]["installed"]}
    assert packages["vendor-addon"]["origin"] == "third_party"
    assert packages["vendor-addon"]["confidence"] == "high"
    assert packages["unproven-addon"]["origin"] == "unknown"


@pytest.mark.parametrize(
    ("data_device", "topology", "expected_risk"),
    [
        ("/dev/sda3", "8:2\tsda\t2\n8:3\tsda\t3\n", "same_physical_disk"),
        ("/dev/sdb1", "8:2\tsda\t2\n8:17\tsdb\t1\n", "different_physical_disk"),
    ],
)
def test_separate_partition_does_not_imply_firmware_overwrite_safety(
    tmp_path, data_device, topology, expected_risk
):
    data_major_minor = "8:3" if data_device == "/dev/sda3" else "8:17"
    fixture = _storage_fixture(
        tmp_path,
        docker_root="/data/docker",
        mounts=(
            "25 1 8:2 / / rw - ext4 /dev/sda2 rw\n"
            f"26 1 {data_major_minor} / /data rw - ext4 {data_device} rw\n"
        ),
    )
    (fixture / "docker-container-mounts.tsv").write_text("")
    (fixture / "docker-volumes.tsv").write_text("")
    (fixture / "block-topology.tsv").write_text(topology)
    report = scan(tmp_path, "local", fixture)
    docker_root = next(item for item in report["storage"]["targets"] if item["kind"] == "docker_root")
    assert docker_root["persistence"] == "separate_mount"
    assert docker_root["firmware_overwrite_risk"] == expected_risk
    assert "safe" not in json.dumps(docker_root).lower()


@pytest.mark.parametrize(
    ("root_disk", "data_disk", "expected"),
    [
        ("nvme0n1", "nvme0n1", "same_physical_disk"),
        ("nvme0n1", "nvme1n1", "different_physical_disk"),
    ],
)
def test_dm_devices_compare_recursive_physical_disk_sets(tmp_path, root_disk, data_disk, expected):
    fixture = _topology_fixture(
        tmp_path,
        "25 1 253:0 / / rw - ext4 /dev/dm-0 rw\n"
        "26 1 253:1 / /data rw - ext4 /dev/dm-1 rw\n",
    )
    root_leaf = _sysfs_block(tmp_path, "259:2", f"{root_disk}p2", disk=root_disk, partition=2)
    data_leaf = _sysfs_block(tmp_path, "259:3", f"{data_disk}p3", disk=data_disk, partition=3)
    dm0 = _sysfs_block(tmp_path, "253:0", "dm-0", virtual=True)
    dm1 = _sysfs_block(tmp_path, "253:1", "dm-1", virtual=True)
    _sysfs_slave(dm0, root_leaf)
    _sysfs_slave(dm1, data_leaf)

    report = scan(tmp_path, "local", fixture)
    target = next(item for item in report["storage"]["targets"] if item["kind"] == "docker_root")
    assert target["firmware_overwrite_risk"] == expected


@pytest.mark.parametrize(
    ("data_disk", "data_major_minor", "expected"),
    [
        ("nvme0n1", "259:3", "same_physical_disk"),
        ("nvme1n1", "259:19", "different_physical_disk"),
    ],
)
def test_ordinary_nvme_partitions_use_physical_parent(tmp_path, data_disk, data_major_minor, expected):
    fixture = _topology_fixture(
        tmp_path,
        "25 1 259:2 / / rw - ext4 /dev/nvme0n1p2 rw\n"
        f"26 1 {data_major_minor} / /data rw - ext4 /dev/{data_disk}p3 rw\n",
    )
    _sysfs_block(tmp_path, "259:2", "nvme0n1p2", disk="nvme0n1", partition=2)
    _sysfs_block(tmp_path, data_major_minor, f"{data_disk}p3", disk=data_disk, partition=3)
    report = scan(tmp_path, "local", fixture)
    assert report["storage"]["targets"][0]["firmware_overwrite_risk"] == expected


@pytest.mark.parametrize(("virtual_name", "virtual_major_minor"), [("dm-1", "253:1"), ("md0", "9:0")])
def test_multi_slave_virtual_device_retains_all_physical_parents(tmp_path, virtual_name, virtual_major_minor):
    fixture = _topology_fixture(
        tmp_path,
        "25 1 8:2 / / rw - ext4 /dev/sda2 rw\n"
        f"26 1 {virtual_major_minor} / /data rw - ext4 /dev/mapper/data rw\n",
    )
    _sysfs_block(tmp_path, "8:2", "sda2", disk="sda", partition=2)
    left = _sysfs_block(tmp_path, "8:17", "sdb1", disk="sdb", partition=1)
    right = _sysfs_block(tmp_path, "8:33", "sdc1", disk="sdc", partition=1)
    virtual = _sysfs_block(tmp_path, virtual_major_minor, virtual_name, virtual=True)
    _sysfs_slave(virtual, left)
    _sysfs_slave(virtual, right)

    local = scan(tmp_path, "local", fixture)
    data_mount = local["storage"]["mount_inventory"]["entries"][1]
    target = local["storage"]["targets"][0]
    assert data_mount["block_resolution"] == "resolved"
    assert set(data_mount["physical_disks"]) == {"sdb", "sdc"}
    assert len(data_mount["physical_disk_ids"]) == 2
    assert data_mount["physical_disk_id"] is None
    assert target["firmware_overwrite_risk"] == "different_physical_disk"

    redacted = scan(tmp_path, "redacted", fixture)
    redacted_mount = redacted["storage"]["mount_inventory"]["entries"][1]
    assert redacted_mount["physical_disks"] is None
    assert redacted_mount["physical_disk_ids"] == data_mount["physical_disk_ids"]
    assert "sdb" not in json.dumps(redacted)


def test_nested_dm_md_chain_resolves_recursively(tmp_path):
    fixture = _topology_fixture(
        tmp_path,
        "25 1 8:2 / / rw - ext4 /dev/sda2 rw\n"
        "26 1 253:1 / /data rw - ext4 /dev/dm-1 rw\n",
    )
    _sysfs_block(tmp_path, "8:2", "sda2", disk="sda", partition=2)
    leaf = _sysfs_block(tmp_path, "8:17", "sdb1", disk="sdb", partition=1)
    md = _sysfs_block(tmp_path, "9:0", "md0", virtual=True)
    dm = _sysfs_block(tmp_path, "253:1", "dm-1", virtual=True)
    _sysfs_slave(md, leaf)
    _sysfs_slave(dm, md)
    report = scan(tmp_path, "local", fixture)
    assert report["storage"]["targets"][0]["firmware_overwrite_risk"] == "different_physical_disk"


@pytest.mark.parametrize("failure", ["missing_slave", "missing_sysfs", "cycle", "depth_limit"])
def test_incomplete_or_invalid_virtual_topology_is_unknown(tmp_path, failure):
    fixture = _topology_fixture(
        tmp_path,
        "25 1 253:0 / / rw - ext4 /dev/dm-0 rw\n"
        "26 1 253:1 / /data rw - ext4 /dev/dm-1 rw\n",
    )
    leaf = _sysfs_block(tmp_path, "8:2", "sda2", disk="sda", partition=2)
    dm0 = _sysfs_block(tmp_path, "253:0", "dm-0", virtual=True)
    _sysfs_slave(dm0, leaf)
    if failure == "missing_sysfs":
        pass
    else:
        dm1 = _sysfs_block(tmp_path, "253:1", "dm-1", virtual=True)
        if failure == "missing_slave":
            broken = tmp_path / "sys/devices/virtual/block/missing-slave"
            broken.mkdir(parents=True)
            _sysfs_slave(dm1, broken)
        elif failure == "cycle":
            _sysfs_slave(dm1, dm0)
            _sysfs_slave(dm0, dm1)
        else:
            parent = dm1
            for index in range(2, 12):
                child = _sysfs_block(tmp_path, f"253:{index}", f"dm-{index}", virtual=True)
                _sysfs_slave(parent, child)
                parent = child
            _sysfs_slave(parent, leaf)

    report = scan(tmp_path, "local", fixture)
    target = report["storage"]["targets"][0]
    assert target["firmware_overwrite_risk"] == "unknown"
    assert report["storage"]["status"] == "partial"
    assert "block_topology_unknown" in report["storage"]["errors"]


def test_logical_names_in_injected_topology_are_not_physical_evidence(tmp_path):
    fixture = _topology_fixture(
        tmp_path,
        "25 1 253:0 / / rw - ext4 /dev/dm-0 rw\n"
        "26 1 253:1 / /data rw - ext4 /dev/dm-1 rw\n",
    )
    (fixture / "block-topology.tsv").write_text(
        "253:0\tdm-0\t-\tcomplete\n253:1\tdm-1\t-\tcomplete\n"
    )
    report = scan(tmp_path, "local", fixture)
    assert report["storage"]["targets"][0]["firmware_overwrite_risk"] == "unknown"


def test_dm_root_and_all_docker_targets_use_the_same_topology_result(tmp_path):
    fixture = _topology_fixture(
        tmp_path,
        "25 1 253:0 / / rw - ext4 /dev/dm-0 rw\n"
        "26 1 8:3 / /data rw - ext4 /dev/sda3 rw\n",
        docker_mounts=(
            "bind\t/data/bind\t/bind\t\n"
            "volume\t/data/volume\t/volume\tvolume-a\n"
        ),
    )
    root_leaf = _sysfs_block(tmp_path, "8:2", "sda2", disk="sda", partition=2)
    _sysfs_block(tmp_path, "8:3", "sda3", disk="sda", partition=3)
    dm0 = _sysfs_block(tmp_path, "253:0", "dm-0", virtual=True)
    _sysfs_slave(dm0, root_leaf)
    report = scan(tmp_path, "local", fixture)
    assert {item["kind"] for item in report["storage"]["targets"]} == {"docker_root", "bind", "volume"}
    assert {item["firmware_overwrite_risk"] for item in report["storage"]["targets"]} == {"same_physical_disk"}


def test_all_container_states_and_unused_volumes_are_in_scan_scope(tmp_path):
    fixture = _storage_fixture(
        tmp_path,
        docker_root="/data/docker",
        mounts=(
            "25 1 8:2 / / rw - ext4 /dev/sda2 rw\n"
            "26 1 8:17 / /data rw - ext4 /dev/sdb1 rw\n"
        ),
    )
    # This fixture represents the result of `docker ps -aq`, including a stopped container.
    (fixture / "docker-container-mounts.tsv").write_text(
        "bind\t/data/stopped-container\t/archive\t\n"
    )
    # The volume is intentionally absent from container mounts: it is discovered by volume inventory.
    (fixture / "docker-volumes.tsv").write_text("orphaned\t/data/docker/volumes/orphaned/_data\n")
    (fixture / "block-topology.tsv").write_text("8:2\tsda\t2\n8:17\tsdb\t1\n")
    report = scan(tmp_path, "local", fixture)
    completeness = report["storage"]["scan_completeness"]
    assert completeness["container_scope"] == "all"
    assert completeness["volume_scope"] == "all"
    assert any(item["source"] == "/data/stopped-container" for item in report["storage"]["targets"])
    assert any(item["kind"] == "volume" and item["name"] == "orphaned" for item in report["storage"]["targets"])


@pytest.mark.parametrize(
    ("marker", "error"),
    [
        ("docker-containers_truncated", "docker_containers_truncated"),
        ("docker-container_inspect_failed", "docker_container_inspect_failed"),
        ("docker-volume_query_failed", "docker_volume_query_failed"),
    ],
)
def test_incomplete_docker_enumeration_is_explicitly_partial(tmp_path, marker, error):
    fixture = _storage_fixture(tmp_path)
    (fixture / "docker-container-mounts.tsv").write_text("")
    (fixture / "docker-volumes.tsv").write_text("")
    (fixture / marker).write_text("")
    report = scan(tmp_path, "local", fixture)
    assert report["storage"]["status"] == "partial"
    assert report["storage"]["scan_completeness"]["mounts"] == "partial"
    assert error in report["storage"]["errors"]


def test_bind_source_symlink_is_resolved_before_longest_mount_match(tmp_path):
    (tmp_path / "data-real/media").mkdir(parents=True)
    (tmp_path / "media-link").symlink_to(tmp_path / "data-real/media")
    fixture = _storage_fixture(
        tmp_path,
        mounts=(
            "25 1 8:2 / / rw - ext4 /dev/sda2 rw\n"
            "26 1 8:17 / /data-real rw - ext4 /dev/sdb1 rw\n"
        ),
    )
    (fixture / "docker-container-mounts.tsv").write_text("bind\t/media-link\t/media\t\n")
    (fixture / "docker-volumes.tsv").write_text("")
    (fixture / "block-topology.tsv").write_text("8:2\tsda\t2\n8:17\tsdb\t1\n")
    report = scan(tmp_path, "local", fixture)
    bind = next(item for item in report["storage"]["targets"] if item["kind"] == "bind")
    assert bind["source"] == "/data-real/media"
    assert bind["mount_id"] == "mount-2"


def test_snapshot_id_changes_with_dynamic_storage_and_identity_evidence(tmp_path):
    fixture = _storage_fixture(tmp_path, docker_root="/data/docker")
    (fixture / "docker-container-mounts.tsv").write_text("")
    (fixture / "docker-volumes.tsv").write_text("")
    (fixture / "uname.txt").write_text("x86_64\n")
    first = scan(tmp_path, "local", fixture)
    redacted = scan(tmp_path, "redacted", fixture)
    assert first["snapshot_id"] == redacted["snapshot_id"]

    (fixture / "docker-info.txt").write_text("/other/docker\n")
    storage_changed = scan(tmp_path, "local", fixture)
    assert storage_changed["snapshot_id"] != first["snapshot_id"]

    (fixture / "docker-info.txt").write_text("/data/docker\n")
    (fixture / "uname.txt").write_text("aarch64\n")
    identity_changed = scan(tmp_path, "local", fixture)
    assert identity_changed["snapshot_id"] != first["snapshot_id"]


def test_dmi_vendor_is_not_legacy_bios_evidence(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/openwrt_release").write_text(
        "DISTRIB_ID='ImmortalWrt'\nDISTRIB_TARGET='x86/64'\nDISTRIB_ARCH='x86_64'\n"
    )
    bios_vendor = tmp_path / "sys/class/dmi/id/bios_vendor"
    bios_vendor.parent.mkdir(parents=True)
    bios_vendor.write_text("Example Vendor\n")
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    (fixture / "uname.txt").write_text("x86_64\n")
    report = scan(tmp_path, fixture_dir=fixture)
    assert report["system"]["boot_mode"] == "unknown"

    (fixture / "boot-mode.txt").write_text("bios\n")
    explicitly_proven = scan(tmp_path, fixture_dir=fixture)
    assert explicitly_proven["system"]["boot_mode"] == "bios"
