include $(TOPDIR)/rules.mk

PKG_NAME:=nopal
PKG_VERSION:=0.1.3-alpha.1
PKG_RELEASE:=1

PKG_LICENSE:=Apache-2.0
PKG_MAINTAINER:=nopal contributors

include $(INCLUDE_DIR)/package.mk

define Package/nopal
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Multi-WAN manager
  DEPENDS:=+nftables +ip-full +kmod-nft-ct +kmod-nft-fib +kmod-nft-numgen
endef

define Package/nopal/description
  Multi-WAN policy routing and failover manager for OpenWrt.
  Single statically-linked Nim binary with zero runtime dependencies.
  Native nftables JSON API, netlink sockets, health probes.
endef

define Package/nopal/conffiles
/etc/config/nopal
endef

# Cross-compilation is handled externally (Nim + crosstool-ng).
# The pre-built binary is expected at $(PKG_BUILD_DIR)/nopald
define Build/Compile
	@echo "Using pre-built binary"
endef

define Package/nopal/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/nopald $(1)/usr/sbin/nopald
	ln -sf /usr/sbin/nopald $(1)/usr/sbin/nopal

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/nopal.init $(1)/etc/init.d/nopal

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/nopal.config $(1)/etc/config/nopal

	$(INSTALL_DIR) $(1)/usr/libexec/rpcd
	$(INSTALL_BIN) ./files/rpcd-nopal $(1)/usr/libexec/rpcd/nopal
endef

$(eval $(call BuildPackage,nopal))
