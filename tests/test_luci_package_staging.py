import io
import os
from pathlib import Path
import shutil
import subprocess
import tarfile


ROOT = Path(__file__).resolve().parents[1]


def test_luci_prepare_callback_stages_complete_executable_package(tmp_path):
    """Exercise the real package Makefile through a minimal pinned luci.mk harness.

    This is a reproducible package-staging/IPK-layout test, not a claim that a
    complete OpenWrt SDK or target toolchain was used.
    """
    workspace = tmp_path / "workspace"
    package = workspace / "luci-app-smart-upgrade"
    scripts = workspace / "scripts"
    shutil.copytree(ROOT / "luci-app-smart-upgrade", package)
    scripts.mkdir(parents=True)
    for name in ("smart-upgrade-agent.sh", "smart-upgrade-storage.sh"):
        shutil.copy2(ROOT / "scripts" / name, scripts / name)

    topdir = tmp_path / "openwrt"
    (topdir / "feeds/luci").mkdir(parents=True)
    (topdir / "rules.mk").write_text(
        "BUILD_DIR:=$(TOPDIR)/build\n"
        "INSTALL_DIR:=install -d -m0755\n"
        "INSTALL_BIN:=install -m0755\n"
        "CP:=cp -fpR\n",
        encoding="utf-8",
    )
    # Match the official callback contract: LUCI_NAME is the package directory
    # and Build/Prepare invokes Build/Prepare/$(LUCI_NAME).
    (topdir / "feeds/luci/luci.mk").write_text(
        "LUCI_NAME?=$(notdir ${CURDIR})\n"
        "PKG_BUILD_DIR:=$(BUILD_DIR)/$(LUCI_NAME)\n"
        "define Build/Prepare\n"
        "\t@rm -rf $(PKG_BUILD_DIR)\n"
        "\t@mkdir -p $(PKG_BUILD_DIR)\n"
        "\t@for d in htdocs root; do if [ -d ./$$d ]; then mkdir -p $(PKG_BUILD_DIR)/$$d; cp -fpR ./$$d/* $(PKG_BUILD_DIR)/$$d/; fi; done\n"
        "\t$(call Build/Prepare/$(LUCI_NAME))\n"
        "endef\n"
        ".PHONY: prepare stage\n"
        "prepare:\n"
        "\t$(Build/Prepare)\n"
        "stage: prepare\n"
        "\t@rm -rf $(TOPDIR)/stage\n"
        "\t@mkdir -p $(TOPDIR)/stage/www\n"
        "\t@cp -fpR $(PKG_BUILD_DIR)/root/* $(TOPDIR)/stage/\n"
        "\t@cp -fpR $(PKG_BUILD_DIR)/htdocs/* $(TOPDIR)/stage/www/\n",
        encoding="utf-8",
    )
    subprocess.run(
        ["make", "stage", f"TOPDIR={topdir}"], cwd=package,
        check=True, capture_output=True, text=True, timeout=30,
    )
    stage = topdir / "stage"
    expected = {
        "usr/libexec/smart-upgrade/smart-upgrade-agent": 0o755,
        "usr/libexec/smart-upgrade/smart-upgrade-storage.sh": 0o755,
        "usr/libexec/rpcd/smart_upgrade": 0o755,
        "usr/share/rpcd/acl.d/luci-app-smart-upgrade.json": 0o644,
        "usr/share/luci/menu.d/luci-app-smart-upgrade.json": 0o644,
        "www/luci-static/resources/view/smart-upgrade/overview.js": 0o644,
    }
    for name, mode in expected.items():
        path = stage / name
        assert path.is_file(), name
        assert path.stat().st_mode & 0o777 == mode

    data = tmp_path / "data.tar.gz"
    with tarfile.open(data, "w:gz") as archive:
        for path in sorted(stage.rglob("*")):
            archive.add(path, arcname=path.relative_to(stage))
    control = tmp_path / "control.tar.gz"
    with tarfile.open(control, "w:gz"):
        pass
    (tmp_path / "debian-binary").write_text("2.0\n", encoding="ascii")
    ipk = tmp_path / "luci-app-smart-upgrade-test.ipk"
    subprocess.run(
        ["ar", "-rcS", str(ipk), "debian-binary", "control.tar.gz", "data.tar.gz"],
        cwd=tmp_path, check=True, capture_output=True, timeout=30,
    )
    payload = subprocess.run(
        ["ar", "p", str(ipk), "data.tar.gz"], check=True,
        capture_output=True, timeout=30,
    ).stdout
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
        members = {member.name.removeprefix("./") for member in archive.getmembers()}
    assert set(expected).issubset(members)
