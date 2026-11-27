# SPDX-License-Identifier: GPL-2.0-only

include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI read-only system scan and migration report viewer
LUCI_DEPENDS:=+luci-base +rpcd +jsonfilter +flock +python3-urllib +python3-openssl +ca-bundle
LUCI_PKGARCH:=all

PKG_MAINTAINER:=OpenWrt Smart Upgrade maintainers
PKG_LICENSE:=GPL-2.0-only

define Build/Prepare/luci-app-smart-upgrade
	$(INSTALL_DIR) $(PKG_BUILD_DIR)/root/usr/libexec/smart-upgrade
	$(INSTALL_BIN) $(CURDIR)/../scripts/smart-upgrade-agent.sh \
		$(PKG_BUILD_DIR)/root/usr/libexec/smart-upgrade/smart-upgrade-agent
	$(INSTALL_BIN) $(CURDIR)/../scripts/smart-upgrade-storage.sh \
		$(PKG_BUILD_DIR)/root/usr/libexec/smart-upgrade/smart-upgrade-storage.sh
endef

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
