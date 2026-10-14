#!/usr/bin/env bash
# ==============================================================================
#  EMXS (Email Exchanger Studio) — Universal Mail Server & Dashboard Installer
#  Compatible with Debian-family (Debian, Ubuntu) & RedHat-family (RHEL, Alma, Rocky, CentOS, Fedora)
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Color definitions
C_RESET="\033[0m"
C_BOLD="\033[1m"
C_GREEN="\033[1;32m"
C_RED="\033[1;31m"
C_YELLOW="\033[1;33m"
C_BLUE="\033[1;34m"
C_CYAN="\033[1;36m"

print_banner() {
    echo -e "${C_CYAN}${C_BOLD}"
    echo "=============================================================================="
    echo "       EMXS — Enterprise Email Exchanger Studio Universal Installer          "
    echo "       Support: Debian / Ubuntu & RHEL / AlmaLinux / Rocky / CentOS / Fedora  "
    echo "=============================================================================="
    echo -e "${C_RESET}"
}

# 1. Root Check
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${C_RED}ERROR: Skrip installer ini harus dijalankan dengan hak akses root (sudo)!${C_RESET}"
    exit 1
fi

# 2. Operating System Detection
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID="$ID"
    OS_LIKE="${ID_LIKE:-$ID}"
    OS_PRETTY="$PRETTY_NAME"
else
    echo -e "${C_RED}ERROR: File /etc/os-release tidak ditemukan. OS tidak didukung.${C_RESET}"
    exit 1
fi

case "$OS_LIKE" in
    *debian*|*ubuntu*)
        OS_FAMILY="debian"
        PKG_MGR="apt-get"
        ;;
    *rhel*|*fedora*|*centos*)
        OS_FAMILY="redhat"
        PKG_MGR="dnf"
        command -v dnf >/dev/null 2>&1 || PKG_MGR="yum"
        ;;
    *)
        case "$OS_ID" in
            ubuntu|debian|linuxmint|pop|elementary)
                OS_FAMILY="debian"
                PKG_MGR="apt-get"
                ;;
            rhel|centos|rocky|almalinux|fedora|ol)
                OS_FAMILY="redhat"
                PKG_MGR="dnf"
                command -v dnf >/dev/null 2>&1 || PKG_MGR="yum"
                ;;
            *)
                echo -e "${C_RED}ERROR: Distribusi Linux '$OS_PRETTY' tidak didukung.${C_RESET}"
                echo "EMXS Installer dirancang untuk keluarga Debian (Ubuntu/Debian) dan RedHat (RHEL/Rocky/Alma/CentOS/Fedora)."
                exit 1
                ;;
        esac
        ;;
esac

# Default Values
DEFAULT_HOSTNAME="$(hostname -f 2>/dev/null || hostname)"
[[ "$DEFAULT_HOSTNAME" =~ \. ]] || DEFAULT_HOSTNAME="mail.example.com"
DEFAULT_DOMAIN="${DEFAULT_HOSTNAME#mail.}"
[[ "$DEFAULT_DOMAIN" == "$DEFAULT_HOSTNAME" ]] && DEFAULT_DOMAIN="${DEFAULT_HOSTNAME#*.}"

# Auto-detect Public IP
DEFAULT_IP="$(curl -s4 --max-time 3 https://ifconfig.me 2>/dev/null || ip route get 1.1.1.1 2>/dev/null | awk '{print $7}' | tr -d '\n')"
[ -z "$DEFAULT_IP" ] && DEFAULT_IP="127.0.0.1"

# Generate random secure passwords
gen_pass() {
    openssl rand -base64 15 | tr -dc 'a-zA-Z0-9' | head -c 16
}

ARG_HOSTNAME=""
ARG_DOMAIN=""
ARG_IP=""
ARG_ADMIN_USER="admin"
ARG_ADMIN_EMAIL=""
ARG_ADMIN_PASS=""
ARG_DB_PASS=""
ARG_RC_DB_PASS=""
ARG_SSL="letsencrypt"
ARG_NON_INTERACTIVE=false

# Parse CLI flags
while [[ $# -gt 0 ]]; do
    case "$1" in
        --hostname) ARG_HOSTNAME="$2"; shift 2 ;;
        --domain) ARG_DOMAIN="$2"; shift 2 ;;
        --ip) ARG_IP="$2"; shift 2 ;;
        --admin-user) ARG_ADMIN_USER="$2"; shift 2 ;;
        --admin-email) ARG_ADMIN_EMAIL="$2"; shift 2 ;;
        --admin-pass) ARG_ADMIN_PASS="$2"; shift 2 ;;
        --db-pass) ARG_DB_PASS="$2"; shift 2 ;;
        --rc-db-pass) ARG_RC_DB_PASS="$2"; shift 2 ;;
        --ssl) ARG_SSL="$2"; shift 2 ;;
        -y|--yes|--non-interactive) ARG_NON_INTERACTIVE=true; shift ;;
        -h|--help)
            echo "Penggunaan: ./install.sh [OPSI]"
            echo ""
            echo "Opsi:"
            echo "  --hostname <FQDN>        Hostname mail server (misal: mail.domain.com)"
            echo "  --domain <DOMAIN>        Domain email utama (misal: domain.com)"
            echo "  --ip <IP>                IP Publik server (misal: 103.147.157.37)"
            echo "  --admin-user <USERNAME>  Username superadmin dashboard (default: admin)"
            echo "  --admin-email <EMAIL>    Email superadmin (default: admin@<domain>)"
            echo "  --admin-pass <PASSWORD>  Password login dashboard superadmin"
            echo "  --db-pass <PASSWORD>     Password PostgreSQL untuk user mailuser"
            echo "  --rc-db-pass <PASSWORD>  Password PostgreSQL untuk user roundcube"
            echo "  --ssl <MODE>             Mode SSL: letsencrypt atau selfsigned (default: letsencrypt)"
            echo "  -y, --non-interactive    Jalankan instalasi otomatis tanpa konfirmasi interaktif"
            echo "  -h, --help               Tampilkan bantuan ini"
            exit 0
            ;;
        *) shift ;;
    esac
done

print_banner
echo -e "${C_BOLD}Deteksi Sistem Operasi:${C_RESET} ${C_GREEN}$OS_PRETTY${C_RESET} (Keluarga: ${C_YELLOW}$OS_FAMILY${C_RESET}, Package Manager: ${C_YELLOW}$PKG_MGR${C_RESET})"
echo ""

# Interactive prompts if non-interactive flag is not set
if [ "$ARG_NON_INTERACTIVE" = false ]; then
    echo -e "${C_BOLD}Konfigurasi Parameter Instalasi:${C_RESET}"
    
    read -rp "1. Hostname Mail Server FQDN [$DEFAULT_HOSTNAME]: " INPUT_HOST
    CONF_HOSTNAME="${INPUT_HOST:-$DEFAULT_HOSTNAME}"

    DERIVED_DOM="${CONF_HOSTNAME#mail.}"
    read -rp "2. Domain Utama Email [$DERIVED_DOM]: " INPUT_DOM
    CONF_DOMAIN="${INPUT_DOM:-$DERIVED_DOM}"

    read -rp "3. IP Publik Server [$DEFAULT_IP]: " INPUT_IP
    CONF_IP="${INPUT_IP:-$DEFAULT_IP}"

    read -rp "4. Username Superadmin Dashboard [$ARG_ADMIN_USER]: " INPUT_U
    CONF_ADMIN_USER="${INPUT_U:-$ARG_ADMIN_USER}"

    DEF_ADMIN_MAIL="admin@$CONF_DOMAIN"
    read -rp "5. Email Superadmin Dashboard [$DEF_ADMIN_MAIL]: " INPUT_M
    CONF_ADMIN_EMAIL="${INPUT_M:-$DEF_ADMIN_MAIL}"

    AUTO_ADMIN_PASS="$(gen_pass)"
    read -rp "6. Password Superadmin Dashboard [$AUTO_ADMIN_PASS]: " INPUT_P
    CONF_ADMIN_PASS="${INPUT_P:-$AUTO_ADMIN_PASS}"

    read -rp "7. Mode Sertifikat SSL (letsencrypt/selfsigned) [letsencrypt]: " INPUT_SSL
    CONF_SSL="${INPUT_SSL:-letsencrypt}"

    CONF_DB_PASS="$(gen_pass)"
    CONF_RC_DB_PASS="$(gen_pass)"

    echo ""
    echo -e "${C_CYAN}Ringkasan Konfigurasi:${C_RESET}"
    echo "  - Hostname : $CONF_HOSTNAME"
    echo "  - Domain   : $CONF_DOMAIN"
    echo "  - IP       : $CONF_IP"
    echo "  - Admin    : $CONF_ADMIN_USER ($CONF_ADMIN_EMAIL)"
    echo "  - SSL Mode : $CONF_SSL"
    echo ""
    read -rp "Mulai instalasi sekarang? (Y/n): " CONFIRM
    CONFIRM="${CONFIRM:-Y}"
    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
        echo "Instalasi dibatalkan."
        exit 0
    fi
else
    CONF_HOSTNAME="${ARG_HOSTNAME:-$DEFAULT_HOSTNAME}"
    CONF_DOMAIN="${ARG_DOMAIN:-$DEFAULT_DOMAIN}"
    CONF_IP="${ARG_IP:-$DEFAULT_IP}"
    CONF_ADMIN_USER="${ARG_ADMIN_USER:-admin}"
    CONF_ADMIN_EMAIL="${ARG_ADMIN_EMAIL:-admin@$CONF_DOMAIN}"
    CONF_ADMIN_PASS="${ARG_ADMIN_PASS:-$(gen_pass)}"
    CONF_DB_PASS="${ARG_DB_PASS:-$(gen_pass)}"
    CONF_RC_DB_PASS="${ARG_RC_DB_PASS:-$(gen_pass)}"
    CONF_SSL="${ARG_SSL:-letsencrypt}"
fi

DES_KEY="$(openssl rand -hex 12)"

echo ""
echo -e "${C_GREEN}>>> Memulai Instalasi EMXS Mail Server... <<<${C_RESET}"
echo ""

# ------------------------------------------------------------------------------
# STEP 1: Package Repositories & Installation
# ------------------------------------------------------------------------------
echo -e "${C_CYAN}=== [1/10] Menyiapkan Repositori & Paket Sistem ===${C_RESET}"

if [ "$OS_FAMILY" = "debian" ]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y --no-install-recommends \
        postfix postfix-pgsql \
        dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd dovecot-pgsql dovecot-sieve dovecot-managesieved \
        postgresql postgresql-contrib \
        redis-server \
        rspamd \
        nginx \
        php-fpm php-pgsql php-mbstring php-intl php-xml php-curl php-zip php-gd php-imagick \
        curl tar git certbot openssl jq unzip ca-certificates golang-go acl
    
    REDIS_SERVICE="redis-server"
    PHP_FPM_SERVICE=$(systemctl list-unit-files 2>/dev/null | grep -oE 'php[0-9.]*-fpm\.service' | head -n 1 || echo "php-fpm.service")
    PHP_FPM_SOCK=$(ls -1 /run/php/php*-fpm.sock 2>/dev/null | head -n 1)
    [ -z "$PHP_FPM_SOCK" ] && PHP_FPM_SOCK="/run/php/php-fpm.sock"
    WEB_USER="www-data"
    WEB_GROUP="www-data"
    RSPAMD_USER="_rspamd"
    RSPAMD_GROUP="_rspamd"

else
    # RedHat Family (RHEL, Alma, Rocky, CentOS, Fedora)
    if ! rpm -q epel-release >/dev/null 2>&1; then
        $PKG_MGR install -y epel-release || true
    fi

    # Enable CRB or powertools if available
    if command -v crb >/dev/null 2>&1; then
        crb enable || true
    elif command -v dnf >/dev/null 2>&1; then
        dnf config-manager --set-enabled crb 2>/dev/null || dnf config-manager --set-enabled powertools 2>/dev/null || true
    fi

    # Rspamd repository for RHEL
    if ! rpm -q rspamd >/dev/null 2>&1; then
        RHEL_VER=$(rpm -E %{rhel} 2>/dev/null || echo "9")
        curl -sL "https://rspamd.com/rpm-stable/centos-${RHEL_VER}/rspamd.repo" -o /etc/yum.repos.d/rspamd.repo 2>/dev/null || true
    fi

    $PKG_MGR install -y \
        postfix postfix-pgsql \
        dovecot dovecot-pgsql dovecot-pigeonhole \
        postgresql-server postgresql-contrib \
        redis \
        rspamd \
        nginx \
        php-fpm php-pgsql php-mbstring php-intl php-xml php-curl php-zip php-gd php-pecl-imagick \
        curl tar git certbot openssl jq unzip ca-certificates golang acl

    REDIS_SERVICE="redis"
    PHP_FPM_SERVICE="php-fpm.service"
    PHP_FPM_SOCK="/run/php-fpm/www.sock"
    WEB_USER="nginx"
    WEB_GROUP="nginx"
    RSPAMD_USER="rspamd"
    RSPAMD_GROUP="rspamd"
fi

# ------------------------------------------------------------------------------
# STEP 2: System Users & Maildir Storage
# ------------------------------------------------------------------------------
echo -e "${C_CYAN}=== [2/10] Mengonfigurasi User vmail & Direktori Storage ===${C_RESET}"
if ! id -u vmail >/dev/null 2>&1; then
    groupadd -g 5000 vmail || true
    useradd -g vmail -u 5000 vmail -d /var/mail/vhosts -m -r || true
fi

mkdir -p /var/mail/vhosts /var/log/mail_archives /etc/emxs /opt/emxs /var/www/emxs_icons
chown -R vmail:vmail /var/mail/vhosts
chmod -R 770 /var/mail/vhosts

# RedHat SELinux policy adjustments
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" != "Disabled" ]; then
    echo "--> Mengonfigurasi konteks keamanan SELinux..."
    setsebool -P httpd_can_network_connect 1 2>/dev/null || true
    setsebool -P nis_enabled 1 2>/dev/null || true
    semanage fcontext -a -t mail_spool_t "/var/mail/vhosts(/.*)?" 2>/dev/null || true
    restorecon -Rv /var/mail/vhosts 2>/dev/null || true
fi

# ------------------------------------------------------------------------------
# STEP 3: PostgreSQL Database Setup
# ------------------------------------------------------------------------------
echo -e "${C_CYAN}=== [3/10] Menginisialisasi Database PostgreSQL ===${C_RESET}"

# RHEL initdb if necessary
if [ "$OS_FAMILY" = "redhat" ]; then
    if [ ! -f /var/lib/pgsql/data/PG_VERSION ]; then
        postgresql-setup --initdb 2>/dev/null || su - postgres -c "initdb -D /var/lib/pgsql/data"
    fi
    # Configure pg_hba.conf to allow md5/scram auth for localhost
    PG_HBA="/var/lib/pgsql/data/pg_hba.conf"
    if [ -f "$PG_HBA" ]; then
        sed -i 's/127.0.0.1\/32            ident/127.0.0.1\/32            md5/g' "$PG_HBA"
        sed -i 's/::1\/128                 ident/::1\/128                 md5/g' "$PG_HBA"
    fi
fi

systemctl enable --now postgresql
systemctl restart postgresql

# Create mailuser and mailserver db
su - postgres -c "psql -tc \"SELECT 1 FROM pg_roles WHERE rolname = 'mailuser'\" | grep -q 1 || psql -c \"CREATE USER mailuser WITH PASSWORD '$CONF_DB_PASS';\""
su - postgres -c "psql -tc \"SELECT 1 FROM pg_database WHERE datname = 'mailserver'\" | grep -q 1 || psql -c \"CREATE DATABASE mailserver OWNER mailuser;\""

# Deploy initial schema
SCHEMA_FILE="$SCRIPT_DIR/sql/init_mailserver.sql"
if [ -f "$SCHEMA_FILE" ]; then
    su - postgres -c "psql -d mailserver -f '$SCHEMA_FILE'"
fi

# Insert initial primary domain
su - postgres -c "psql -d mailserver -c \"INSERT INTO domains (name, is_active) VALUES ('$CONF_DOMAIN', TRUE) ON CONFLICT (name) DO NOTHING;\""

# Create roundcube database & user
su - postgres -c "psql -tc \"SELECT 1 FROM pg_roles WHERE rolname = 'roundcube'\" | grep -q 1 || psql -c \"CREATE USER roundcube WITH PASSWORD '$CONF_RC_DB_PASS';\""
su - postgres -c "psql -tc \"SELECT 1 FROM pg_database WHERE datname = 'roundcubemail'\" | grep -q 1 || psql -c \"CREATE DATABASE roundcubemail OWNER roundcube;\""
su - postgres -c "psql -d roundcubemail -c \"GRANT ALL ON SCHEMA public TO roundcube;\""

# ------------------------------------------------------------------------------
# STEP 4: SSL Certificate Setup
# ------------------------------------------------------------------------------
echo -e "${C_CYAN}=== [4/10] Menyiapkan Sertifikat SSL / TLS ===${C_RESET}"
mkdir -p /etc/emxs/ssl

SSL_CERT="/etc/emxs/ssl/fullchain.pem"
SSL_KEY="/etc/emxs/ssl/privkey.pem"

if [ "$CONF_SSL" = "letsencrypt" ]; then
    echo "--> Mencoba penerbitan sertifikat Let's Encrypt untuk $CONF_HOSTNAME ..."
    if certbot certonly --standalone -d "$CONF_HOSTNAME" --non-interactive --agree-tos -m "$CONF_ADMIN_EMAIL" --keep-until-expiring 2>/dev/null; then
        SSL_CERT="/etc/letsencrypt/live/$CONF_HOSTNAME/fullchain.pem"
        SSL_KEY="/etc/letsencrypt/live/$CONF_HOSTNAME/privkey.pem"
        echo -e "${C_GREEN}✔ Let's Encrypt SSL berhasil dipasang!${C_RESET}"
    else
        echo -e "${C_YELLOW}⚠ Let's Encrypt gagal (mungkin DNS belum mengarah). Menggunakan self-signed sementara.${C_RESET}"
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$SSL_KEY" -out "$SSL_CERT" \
            -subj "/CN=$CONF_HOSTNAME/O=EMXS/C=ID" 2>/dev/null || true
    fi
else
    echo "--> Membuat sertifikat SSL Self-Signed..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$SSL_KEY" -out "$SSL_CERT" \
        -subj "/CN=$CONF_HOSTNAME/O=EMXS/C=ID" 2>/dev/null || true
fi

# ------------------------------------------------------------------------------
# STEP 5: Dovecot IMAP/POP3/LMTP & ManageSieve Setup
# ------------------------------------------------------------------------------
echo -e "${C_CYAN}=== [5/10] Mengonfigurasi Dovecot & ManageSieve ===${C_RESET}"
mkdir -p /etc/dovecot/conf.d /etc/dovecot/sieve

# Dovecot SQL ext
sed -e "s|{{DB_PASSWORD}}|$CONF_DB_PASS|g" \
    "$SCRIPT_DIR/templates/dovecot/dovecot-sql.conf.ext.template" > /etc/dovecot/dovecot-sql.conf.ext
chown root:dovecot /etc/dovecot/dovecot-sql.conf.ext
chmod 640 /etc/dovecot/dovecot-sql.conf.ext

# Config files
cp "$SCRIPT_DIR/templates/dovecot/10-mail.conf.template" /etc/dovecot/conf.d/10-mail.conf
cp "$SCRIPT_DIR/templates/dovecot/10-auth.conf.template" /etc/dovecot/conf.d/10-auth.conf
cp "$SCRIPT_DIR/templates/dovecot/auth-sql.conf.ext.template" /etc/dovecot/conf.d/auth-sql.conf.ext
cp "$SCRIPT_DIR/templates/dovecot/10-master.conf.template" /etc/dovecot/conf.d/10-master.conf
cp "$SCRIPT_DIR/templates/dovecot/20-lmtp.conf.template" /etc/dovecot/conf.d/20-lmtp.conf

sed -e "s|{{SSL_CERT}}|$SSL_CERT|g" \
    -e "s|{{SSL_KEY}}|$SSL_KEY|g" \
    "$SCRIPT_DIR/templates/dovecot/10-ssl.conf.template" > /etc/dovecot/conf.d/10-ssl.conf

# Sieve default rule
cp "$SCRIPT_DIR/templates/dovecot/sieve/default.sieve.template" /etc/dovecot/sieve/default.sieve
sievec /etc/dovecot/sieve/default.sieve 2>/dev/null || true
chown -R vmail:vmail /etc/dovecot/sieve
chmod -R 755 /etc/dovecot/sieve

# ------------------------------------------------------------------------------
# STEP 6: Postfix MTA Setup
# ------------------------------------------------------------------------------
echo -e "${C_CYAN}=== [6/10] Mengonfigurasi Postfix MTA ===${C_RESET}"
mkdir -p /etc/postfix/pgsql

sed -e "s|{{DB_PASSWORD}}|$CONF_DB_PASS|g" \
    "$SCRIPT_DIR/templates/postfix/pgsql/virtual_mailbox_domains.cf.template" > /etc/postfix/pgsql/virtual_mailbox_domains.cf

sed -e "s|{{DB_PASSWORD}}|$CONF_DB_PASS|g" \
    "$SCRIPT_DIR/templates/postfix/pgsql/virtual_mailbox_maps.cf.template" > /etc/postfix/pgsql/virtual_mailbox_maps.cf

sed -e "s|{{DB_PASSWORD}}|$CONF_DB_PASS|g" \
    "$SCRIPT_DIR/templates/postfix/pgsql/virtual_alias_maps.cf.template" > /etc/postfix/pgsql/virtual_alias_maps.cf

chmod 640 /etc/postfix/pgsql/*
chown root:postfix /etc/postfix/pgsql/*

echo "$CONF_HOSTNAME" > /etc/mailname

sed -e "s|{{SERVER_HOSTNAME}}|$CONF_HOSTNAME|g" \
    -e "s|{{SSL_CERT}}|$SSL_CERT|g" \
    -e "s|{{SSL_KEY}}|$SSL_KEY|g" \
    "$SCRIPT_DIR/templates/postfix/main.cf.template" > /etc/postfix/main.cf

cp "$SCRIPT_DIR/templates/postfix/master.cf.template" /etc/postfix/master.cf

# ------------------------------------------------------------------------------
# STEP 7: Redis & Rspamd Anti-Spam Setup
# ------------------------------------------------------------------------------
echo -e "${C_CYAN}=== [7/10] Mengonfigurasi Rspamd & DKIM Signing ===${C_RESET}"
mkdir -p /var/lib/rspamd/dkim /etc/rspamd/local.d /etc/rspamd/maps.d
chown -R "$RSPAMD_USER:$RSPAMD_GROUP" /var/lib/rspamd/dkim

cp "$SCRIPT_DIR/templates/rspamd/redis.conf.template" /etc/rspamd/local.d/redis.conf
cp "$SCRIPT_DIR/templates/rspamd/milter_headers.conf.template" /etc/rspamd/local.d/milter_headers.conf
cp "$SCRIPT_DIR/templates/rspamd/arc.conf.template" /etc/rspamd/local.d/arc.conf
cp "$SCRIPT_DIR/templates/rspamd/dkim_signing.conf.template" /etc/rspamd/local.d/dkim_signing.conf
cp "$SCRIPT_DIR/templates/rspamd/multimap.conf.template" /etc/rspamd/local.d/multimap.conf
cp "$SCRIPT_DIR/templates/rspamd/actions.conf.template" /etc/rspamd/local.d/actions.conf

cp "$SCRIPT_DIR/templates/rspamd/maps/"* /etc/rspamd/maps.d/
chown -R "$RSPAMD_USER:$RSPAMD_GROUP" /etc/rspamd/maps.d /etc/rspamd/local.d
chmod 644 /etc/rspamd/maps.d/*

# Generate initial DKIM for primary domain
DKIM_KEY_PATH="/var/lib/rspamd/dkim/$CONF_DOMAIN.mail.key"
if [ ! -f "$DKIM_KEY_PATH" ]; then
    rspamadm dkim_keygen -d "$CONF_DOMAIN" -s mail -k "$DKIM_KEY_PATH" > /tmp/dkim_gen.txt 2>/dev/null || true
    chown "$RSPAMD_USER:$RSPAMD_GROUP" "$DKIM_KEY_PATH" 2>/dev/null || true
    chmod 600 "$DKIM_KEY_PATH" 2>/dev/null || true
fi

# ------------------------------------------------------------------------------
# STEP 8: Roundcube Webmail Deployment
# ------------------------------------------------------------------------------
echo -e "${C_CYAN}=== [8/10] Memasang Roundcube Webmail Terbaru ===${C_RESET}"
mkdir -p /var/www

if [ ! -f "/var/www/roundcube/public_html/index.php" ]; then
    echo "--> Mendownload paket resmi Roundcube terbaru..."
    cd /tmp
    RC_VER=$(curl -sL https://api.github.com/repos/roundcube/roundcubemail/releases/latest 2>/dev/null | grep '"tag_name":' | head -n 1 | sed -E 's/.*"([^"]+)".*/\1/' || echo "1.6.9")
    [ -z "$RC_VER" ] && RC_VER="1.6.9"
    
    curl -sL "https://github.com/roundcube/roundcubemail/releases/download/${RC_VER}/roundcubemail-${RC_VER}-complete.tar.gz" -o roundcube.tar.gz
    tar -xzf roundcube.tar.gz
    rm -rf /var/www/roundcube
    mv "roundcubemail-${RC_VER}" /var/www/roundcube
    rm -f roundcube.tar.gz
fi

ln -sfn /var/www/roundcube/public_html /var/www/webmail

# Import Roundcube SQL schema
if ! su - postgres -c "psql -d roundcubemail -tc \"SELECT 1 FROM information_schema.tables WHERE table_name = 'users'\"" | grep -q 1; then
    echo "--> Mengimpor skema database Roundcube..."
    su - postgres -c "psql -d roundcubemail -f /var/www/roundcube/SQL/postgres.initial.sql"
    su - postgres -c "psql -d roundcubemail -c \"GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO roundcube;\""
    su - postgres -c "psql -d roundcubemail -c \"GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO roundcube;\""
fi

# Roundcube Config
sed -e "s|{{RC_DB_PASSWORD}}|$CONF_RC_DB_PASS|g" \
    -e "s|{{DES_KEY}}|$DES_KEY|g" \
    "$SCRIPT_DIR/templates/roundcube/config.inc.php.template" > /var/www/roundcube/config/config.inc.php

# ManageSieve plugin
mkdir -p /var/www/roundcube/plugins/managesieve
cp "$SCRIPT_DIR/templates/roundcube/managesieve.config.inc.php.template" /var/www/roundcube/plugins/managesieve/config.inc.php

mkdir -p /var/www/roundcube/temp /var/www/roundcube/logs
chown -R "$WEB_USER:$WEB_GROUP" /var/www/roundcube
chmod -R 755 /var/www/roundcube
chmod -R 777 /var/www/roundcube/temp /var/www/roundcube/logs

# Nginx Internal Roundcube Listener on Port 8088
mkdir -p /etc/nginx/conf.d /etc/nginx/sites-available /etc/nginx/sites-enabled
sed -e "s|{{PHP_FPM_SOCK}}|$PHP_FPM_SOCK|g" \
    "$SCRIPT_DIR/templates/nginx/roundcube.conf.template" > /etc/nginx/conf.d/roundcube.conf

# Clean default nginx sites
rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true

# ------------------------------------------------------------------------------
# STEP 9: EMXS Management Dashboard & API
# ------------------------------------------------------------------------------
echo -e "${C_CYAN}=== [9/10] Membangun & Memasang EMXS Management Dashboard ===${C_RESET}"
mkdir -p /opt/emxs /etc/emxs

# Copy source code
if [ -d "$SCRIPT_DIR/src/mail-api" ]; then
    cp -r "$SCRIPT_DIR/src/mail-api/"* /opt/emxs/
elif [ -d "/root/mail-api" ]; then
    cp -r /root/mail-api/* /opt/emxs/
fi

# Copy branding icons
if [ -d "$SCRIPT_DIR/assets/icons" ]; then
    cp -r "$SCRIPT_DIR/assets/icons/"* /var/www/emxs_icons/ 2>/dev/null || true
elif [ -d "/var/www/emxs_icons" ]; then
    # Keep existing icons
    true
fi

# Compile Go binary
cd /opt/emxs
echo "--> Mengompilasi binary mail-api Go..."
go build -o /usr/local/bin/mail-api .
chmod +x /usr/local/bin/mail-api

# Write environment configuration
cat << EOF > /etc/emxs/emxs.env
EMXS_SERVER_HOST=$CONF_HOSTNAME
EMXS_PRIMARY_DOMAIN=$CONF_DOMAIN
EMXS_SERVER_IP=$CONF_IP
EMXS_DB_CONN=host=localhost port=5432 user=mailuser password=$CONF_DB_PASS dbname=mailserver sslmode=disable
PORT=8080
EMXS_SSL_CERT=$SSL_CERT
EMXS_SSL_KEY=$SSL_KEY
EMXS_ADMIN_USER=$CONF_ADMIN_USER
EMXS_ADMIN_EMAIL=$CONF_ADMIN_EMAIL
EMXS_ADMIN_PASS=$CONF_ADMIN_PASS
EOF
chmod 600 /etc/emxs/emxs.env

# Install Systemd service
cp "$SCRIPT_DIR/emxs.service" /etc/systemd/system/mail-api.service
systemctl daemon-reload
systemctl enable mail-api

# Install CLI tool
cp "$SCRIPT_DIR/emxs.sh" /usr/local/bin/emxs
chmod +x /usr/local/bin/emxs

# ------------------------------------------------------------------------------
# STEP 10: Firewall & Starting Services
# ------------------------------------------------------------------------------
echo -e "${C_CYAN}=== [10/10] Mengaktifkan Layanan & Firewall ===${C_RESET}"

# Firewall configuration
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    echo "--> Membuka port di UFW Firewall..."
    for p in 25 80 110 143 443 465 587 993 995 4190 8080; do
        ufw allow "${p}/tcp" >/dev/null 2>&1 || true
    done
elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
    echo "--> Membuka port di Firewalld..."
    firewall-cmd --permanent --add-service={smtp,smtps,smtp-submission,imap,imaps,pop3,pop3s,http,https} 2>/dev/null || true
    firewall-cmd --permanent --add-port={4190/tcp,8080/tcp} 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
fi

# Enable and start all services
echo "--> Memulai seluruh layanan mail stack..."
systemctl enable "$REDIS_SERVICE" rspamd dovecot postfix "$PHP_FPM_SERVICE" nginx mail-api 2>/dev/null || true
systemctl restart "$REDIS_SERVICE" postgresql rspamd dovecot postfix "$PHP_FPM_SERVICE" nginx mail-api

# Generate credentials receipt
RECEIPT_FILE="/root/emxs-credentials.txt"
cat << EOF > "$RECEIPT_FILE"
==============================================================================
           EMXS EMAIL EXCHANGER STUDIO — BUKTI INSTALASI & KREDENSIAL         
==============================================================================
Tanggal Instalasi : $(date)
Sistem Operasi    : $OS_PRETTY ($OS_FAMILY)
Server Hostname   : $CONF_HOSTNAME
Domain Utama      : $CONF_DOMAIN
Server IP Publik  : $CONF_IP

AKSES WEB DASHBOARD & WEBMAIL:
------------------------------------------------------------------------------
* Dashboard URL   : https://$CONF_HOSTNAME/ (atau https://$CONF_IP/)
  Username        : $CONF_ADMIN_USER
  Email           : $CONF_ADMIN_EMAIL
  Password        : $CONF_ADMIN_PASS
  2FA / OTP       : Default Nonaktif (Dapat diaktifkan di menu Users)

* Webmail URL     : https://$CONF_HOSTNAME/webmail/

PARAMETER KONEKSI EMAIL CLIENT (OUTLOOK, THUNDERBIRD, ANDROID, IOS):
------------------------------------------------------------------------------
* Incoming Server : $CONF_HOSTNAME
  - IMAP          : Port 993 (SSL/TLS)
  - POP3          : Port 995 (SSL/TLS)
* Outgoing Server : $CONF_HOSTNAME
  - SMTP Subm     : Port 587 (STARTTLS) atau Port 465 (SSL/TLS)
  - Username      : Alamat email lengkap akun
  - Password      : Password akun email

DATABASE KREDENSIAL:
------------------------------------------------------------------------------
* Database Host   : localhost (Port 5432)
* Mail DB / User  : mailserver / mailuser (Password: $CONF_DB_PASS)
* Webmail DB/User : roundcubemail / roundcube (Password: $CONF_RC_DB_PASS)

DNS RECORDS YANG HARUS DITAMBAHKAN DI DOMAIN PROVIDER ($CONF_DOMAIN):
------------------------------------------------------------------------------
1. A Record:
   Host: mail.$CONF_DOMAIN  -> IP: $CONF_IP

2. MX Record:
   Host: @                  -> Target: $CONF_HOSTNAME (Priority: 10)

3. SPF Record (TXT):
   Host: @                  -> Value: v=spf1 +mx +ip4:$CONF_IP ~all
   (Tips: Sisipkan +ip4:IP_LAIN sebelum ~all jika punya IP tambahan)

4. DMARC Record (TXT):
   Host: _dmarc             -> Value: v=DMARC1; p=quarantine; rua=mailto:admin@$CONF_DOMAIN; sp=quarantine; aspf=r;

5. DKIM Record (TXT):
   Host: mail._domainkey    -> Kunci publik dapat dilihat di Dashboard menu DKIM / Domains

PERINTAH MANAJEMEN:
------------------------------------------------------------------------------
* Cek status kesehatan : emxs status
* Restart layanan      : emxs restart
* Pasang SSL Certbot   : emxs certbot $CONF_HOSTNAME $CONF_ADMIN_EMAIL
* Reset kata sandi     : emxs reset-admin
* Informasi instalasi  : emxs info
* Pantau log langsung  : emxs logs
==============================================================================
EOF

echo ""
echo -e "${C_GREEN}${C_BOLD}"
echo "=============================================================================="
echo "      SELAMAT! INSTALASI EMXS MAIL SERVER TELAH SELESAI DENGAN SUKSES!        "
echo "=============================================================================="
echo -e "${C_RESET}"
echo -e "Akses Dashboard : ${C_CYAN}https://$CONF_HOSTNAME/${C_RESET} (atau https://$CONF_IP/)"
echo -e "Akses Webmail   : ${C_CYAN}https://$CONF_HOSTNAME/webmail/${C_RESET}"
echo -e "Username        : ${C_BOLD}$CONF_ADMIN_USER${C_RESET}"
echo -e "Password        : ${C_YELLOW}$CONF_ADMIN_PASS${C_RESET}"
echo ""
echo -e "Bukti instalasi & kredensial lengkap tersimpan di: ${C_BOLD}$RECEIPT_FILE${C_RESET}"
echo -e "Gunakan perintah ${C_GREEN}emxs status${C_RESET} untuk memeriksa kesehatan server kapan saja."
echo "=============================================================================="
