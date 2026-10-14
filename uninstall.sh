#!/usr/bin/env bash
# EMXS (Email Exchanger Studio) Uninstaller
# Safe cleanup & removal tool

set -e

# Detect OS family
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_LIKE="${ID_LIKE:-$ID}"
    case "$OS_LIKE" in
        *debian*|*ubuntu*) OS_FAMILY="debian" ;;
        *) OS_FAMILY="redhat" ;;
    esac
else
    OS_FAMILY="debian"
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Skrip uninstaller harus dijalankan sebagai root (sudo)!"
    exit 1
fi

echo "=========================================================="
echo "    EMXS Mail Server — Uninstaller / Cleanup Script      "
echo "=========================================================="
echo "PERINGATAN: Tindakan ini akan menghentikan seluruh layanan"
echo "mail server (Postfix, Dovecot, Rspamd, Roundcube, mail-api)!"
echo ""
read -rp "Apakah Anda yakin ingin melanjutkan pencopotan? (ketik 'yes' untuk konfirmasi): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    echo "Pencopotan dibatalkan."
    exit 0
fi

read -rp "Apakah Anda ingin membuat BACKUP data mailbox & database terlebih dahulu? (Y/n): " DO_BACKUP
DO_BACKUP="${DO_BACKUP:-Y}"

if [[ "$DO_BACKUP" =~ ^[Yy]$ ]]; then
    BACKUP_DIR="/root/emxs_backup_$(date +%Y%m%d_%H%M%S)"
    echo "--> Membuat backup ke $BACKUP_DIR ..."
    mkdir -p "$BACKUP_DIR"
    
    # Backup mail storage
    if [ -d /var/mail/vhosts ]; then
        echo "    Mengarsipkan /var/mail/vhosts ..."
        tar -czf "$BACKUP_DIR/vhosts_backup.tar.gz" -C /var/mail vhosts 2>/dev/null || true
    fi

    # Backup database
    if command -v pg_dump >/dev/null 2>&1; then
        echo "    Membuat dump database PostgreSQL ..."
        su - postgres -c "pg_dump mailserver" > "$BACKUP_DIR/mailserver.sql" 2>/dev/null || true
        su - postgres -c "pg_dump roundcubemail" > "$BACKUP_DIR/roundcubemail.sql" 2>/dev/null || true
    fi

    # Backup env
    if [ -f /etc/emxs/emxs.env ]; then
        cp /etc/emxs/emxs.env "$BACKUP_DIR/"
    fi

    echo "✔ Backup berhasil disimpan di: $BACKUP_DIR"
fi

echo "--> Menghentikan dan menonaktifkan layanan EMXS..."
systemctl stop mail-api 2>/dev/null || true
systemctl disable mail-api 2>/dev/null || true
rm -f /etc/systemd/system/mail-api.service
systemctl daemon-reload

systemctl stop postfix dovecot rspamd nginx 2>/dev/null || true

# Remove EMXS binaries and config
rm -f /usr/local/bin/mail-api
rm -f /usr/local/bin/emxs
rm -rf /opt/emxs
rm -rf /etc/emxs

# Remove Roundcube web files if requested
read -rp "Hapus instalasi Roundcube Webmail di /var/www/roundcube? (y/N): " DEL_RC
if [[ "$DEL_RC" =~ ^[Yy]$ ]]; then
    rm -rf /var/www/roundcube
    rm -rf /var/www/webmail
    rm -f /etc/nginx/sites-enabled/roundcube
    rm -f /etc/nginx/sites-available/roundcube
    rm -f /etc/nginx/conf.d/roundcube.conf
fi

echo ""
echo "=========================================================="
echo "  EMXS Mail Management telah berhasil dicopot dari sistem."
echo "=========================================================="
