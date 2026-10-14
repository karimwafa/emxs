#!/usr/bin/env bash
# EMXS (Email Exchanger Studio) CLI Helper
# Management utility for EMXS mailserver stack

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

# Load EMXS Environment
if [ -f /etc/emxs/emxs.env ]; then
    . /etc/emxs/emxs.env
fi

# Colors
C_RESET="\033[0m"
C_BOLD="\033[1m"
C_GREEN="\033[1;32m"
C_RED="\033[1;31m"
C_YELLOW="\033[1;33m"
C_BLUE="\033[1;34m"
C_CYAN="\033[1;36m"

# Service names based on OS
if [ "$OS_FAMILY" = "debian" ]; then
    SVC_REDIS="redis-server"
    SVC_PHP=$(systemctl list-unit-files 2>/dev/null | grep -oE 'php[0-9.]*-fpm\.service' | head -n 1 || echo "php-fpm")
else
    SVC_REDIS="redis"
    SVC_PHP="php-fpm"
fi

show_banner() {
    echo -e "${C_CYAN}${C_BOLD}"
    echo "=========================================================="
    echo "      EMXS — Email Exchanger Studio Management CLI       "
    echo "=========================================================="
    echo -e "${C_RESET}"
}

cmd_status() {
    show_banner
    echo -e "${C_BOLD}▶ Status Layanan Server:${C_RESET}"
    
    services=("postgresql" "$SVC_REDIS" "rspamd" "dovecot" "postfix" "$SVC_PHP" "nginx" "mail-api")
    for svc in "${services[@]}"; do
        if [ -z "$svc" ]; then continue; fi
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            printf "  %-22s : ${C_GREEN}✔ RUNNING${C_RESET}\n" "$svc"
        else
            printf "  %-22s : ${C_RED}✖ STOPPED / FAILED${C_RESET}\n" "$svc"
        fi
    done

    echo ""
    echo -e "${C_BOLD}▶ Status Port Jaringan:${C_RESET}"
    ports=(
        "25:SMTP (Incoming MTA)"
        "465:SMTPS (SSL)"
        "587:Submission (STARTTLS)"
        "110:POP3"
        "995:POP3S (SSL)"
        "143:IMAP"
        "993:IMAPS (SSL)"
        "4190:ManageSieve"
        "80:HTTP (Web / ACME)"
        "443:HTTPS (EMXS Dashboard)"
        "8088:Roundcube Internal"
    )

    for item in "${ports[@]}"; do
        p="${item%%:*}"
        desc="${item#*:}"
        if ss -tulpn 2>/dev/null | grep -q ":$p "; then
            printf "  Port %-5s %-25s : ${C_GREEN}✔ LISTENING${C_RESET}\n" "$p" "($desc)"
        else
            printf "  Port %-5s %-25s : ${C_YELLOW}⚠ OFFLINE${C_RESET}\n" "$p" "($desc)"
        fi
    done
    echo ""
}

cmd_restart() {
    show_banner
    echo -e "${C_YELLOW}Restarting all mail stack services in dependency order...${C_RESET}"
    systemctl restart postgresql
    systemctl restart "$SVC_REDIS"
    systemctl restart rspamd
    systemctl restart dovecot
    systemctl restart postfix
    systemctl restart "$SVC_PHP"
    systemctl restart nginx
    systemctl restart mail-api
    echo -e "${C_GREEN}✔ Semua layanan berhasil direstart!${C_RESET}"
}

cmd_certbot() {
    show_banner
    DOM="${1:-$EMXS_SERVER_HOST}"
    EMAIL="${2:-$EMXS_ADMIN_EMAIL}"
    
    if [ -z "$DOM" ]; then
        echo -e "${C_RED}Error: Hostname belum dispesifikasikan.${C_RESET}"
        echo "Contoh: emxs certbot mail.domainanda.com admin@domainanda.com"
        exit 1
    fi

    echo -e "${C_CYAN}Memohon sertifikat Let's Encrypt untuk: $DOM ...${C_RESET}"
    
    # Hentikan port 80 sementara atau gunakan certbot webroot/standalone
    systemctl stop mail-api 2>/dev/null || true
    
    if certbot certonly --standalone -d "$DOM" --non-interactive --agree-tos -m "$EMAIL" --keep-until-expiring; then
        echo -e "${C_GREEN}✔ Sertifikat SSL Let's Encrypt berhasil diterbitkan!${C_RESET}"
        
        CERT_PATH="/etc/letsencrypt/live/$DOM/fullchain.pem"
        KEY_PATH="/etc/letsencrypt/live/$DOM/privkey.pem"

        # Update Postfix
        postconf -e "smtpd_tls_cert_file = $CERT_PATH"
        postconf -e "smtpd_tls_key_file = $KEY_PATH"
        systemctl reload postfix

        # Update Dovecot
        sed -i "s|ssl_cert = .*|ssl_cert = <$CERT_PATH|g" /etc/dovecot/conf.d/10-ssl.conf 2>/dev/null || true
        sed -i "s|ssl_key = .*|ssl_key = <$KEY_PATH|g" /etc/dovecot/conf.d/10-ssl.conf 2>/dev/null || true
        systemctl reload dovecot

        # Update EMXS Env
        if [ -f /etc/emxs/emxs.env ]; then
            sed -i "s|EMXS_SSL_CERT=.*|EMXS_SSL_CERT=$CERT_PATH|g" /etc/emxs/emxs.env
            sed -i "s|EMXS_SSL_KEY=.*|EMXS_SSL_KEY=$KEY_PATH|g" /etc/emxs/emxs.env
        fi
    else
        echo -e "${C_RED}✖ Gagal menerbitkan sertifikat Let's Encrypt. Pastikan DNS A-Record $DOM sudah mengarah ke server ini!${C_RESET}"
    fi

    systemctl start mail-api
}

cmd_reset_admin() {
    show_banner
    USER_NAME="${1:-admin}"
    echo -e "${C_YELLOW}Reset kata sandi administrator: $USER_NAME${C_RESET}"
    read -rsp "Masukkan kata sandi baru: " NEW_PASS
    echo ""
    if [ -z "$NEW_PASS" ]; then
        echo -e "${C_RED}Kata sandi tidak boleh kosong!${C_RESET}"
        exit 1
    fi

    # Hash via python bcrypt
    python3 - << PYEOF
import bcrypt
import subprocess

pass_raw = """$NEW_PASS""".encode('utf-8')
salt = bcrypt.gensalt(10)
hashed = bcrypt.hashpw(pass_raw, salt).decode('utf-8')

cmd = ["su", "-", "postgres", "-c", f"psql -d mailserver -c \"UPDATE dashboard_users SET password_hash = '{hashed}', otp_enabled = FALSE WHERE username = '$USER_NAME';\""]
res = subprocess.run(cmd, capture_output=True, text=True)
if res.returncode == 0:
    print("\033[1;32m✔ Kata sandi berhasil diperbarui dan 2FA dinonaktifkan!\033[0m")
else:
    print("\033[1;31m✖ Gagal memperbarui kata sandi:\033[0m", res.stderr)
PYEOF
}

cmd_info() {
    show_banner
    if [ -f /root/emxs-credentials.txt ]; then
        cat /root/emxs-credentials.txt
    elif [ -f /etc/emxs/emxs.env ]; then
        echo -e "${C_BOLD}Server Host :${C_RESET} ${EMXS_SERVER_HOST:-localhost}"
        echo -e "${C_BOLD}Primary Dom :${C_RESET} ${EMXS_PRIMARY_DOMAIN:-example.com}"
        echo -e "${C_BOLD}Server IP   :${C_RESET} ${EMXS_SERVER_IP:-127.0.0.1}"
        echo -e "${C_BOLD}Dashboard   :${C_RESET} https://${EMXS_SERVER_HOST:-localhost}/"
        echo -e "${C_BOLD}Webmail     :${C_RESET} https://${EMXS_SERVER_HOST:-localhost}/webmail/"
    else
        echo "Belum ada informasi instalasi tersimpan."
    fi
}

cmd_logs() {
    show_banner
    echo -e "${C_CYAN}Streaming live logs (Tekan Ctrl+C untuk berhenti)...${C_RESET}"
    journalctl -u postfix -u dovecot -u mail-api -f
}

case "$1" in
    status) cmd_status ;;
    restart) cmd_restart ;;
    certbot) cmd_certbot "$2" "$3" ;;
    reset-admin) cmd_reset_admin "$2" ;;
    info) cmd_info ;;
    logs) cmd_logs ;;
    *)
        show_banner
        echo "Penggunaan: emxs <perintah>"
        echo ""
        echo "Perintah yang tersedia:"
        echo "  status            Melihat status kesehatan layanan & port mail server"
        echo "  restart           Merestart seluruh layanan stack secara berurutan"
        echo "  certbot [dom]     Menerbitkan/memperbarui sertifikat Let's Encrypt"
        echo "  reset-admin [usr] Mereset kata sandi superadmin dashboard"
        echo "  info              Melihat informasi akses & DNS panduan"
        echo "  logs              Melihat streaming log sistem & mailer"
        echo ""
        ;;
esac
