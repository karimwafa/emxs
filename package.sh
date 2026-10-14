#!/usr/bin/env bash
# EMXS Installer Packaging Utility
# Bundles the installer, source code, and assets into a portable deployment archive

set -e
PKG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "--> Menyelaraskan source code & assets ke dalam paket installer..."
mkdir -p "$PKG_DIR/src/mail-api" "$PKG_DIR/assets/icons"

# Copy latest mail-api source code
if [ -f "/root/mail-api/main.go" ]; then
    cp -rf /root/mail-api/* "$PKG_DIR/src/mail-api/"
    echo "  [OK] Source code mail-api berhasil disinkronkan."
fi

# Copy branding icons
if [ -d "/var/www/emxs_icons" ]; then
    cp -rf /var/www/emxs_icons/* "$PKG_DIR/assets/icons/" 2>/dev/null || true
    echo "  [OK] Asset branding icons berhasil disinkronkan."
fi

echo "--> Membuat arsip mandiri: /root/emxs-installer.tar.gz ..."
cd /root
tar -czf /root/emxs-installer.tar.gz emxs-installer/

echo "=========================================================="
echo "✔ ARSIP INSTALASI MANDIRI BERHASIL DIBUAT!"
echo "  Lokasi File : /root/emxs-installer.tar.gz"
echo "  Ukuran      : $(du -sh /root/emxs-installer.tar.gz 2>/dev/null | awk '{print $1}')"
echo ""
echo "Cara transfer & pasang di server baru (Debian/RedHat):"
echo "  1. scp /root/emxs-installer.tar.gz root@IP_SERVER_BARU:~/"
echo "  2. Di server baru:"
echo "     tar -xzf emxs-installer.tar.gz"
echo "     cd emxs-installer"
echo "     sudo ./install.sh"
echo "=========================================================="
