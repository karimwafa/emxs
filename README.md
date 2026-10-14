# EMXS (Enterprise Email Exchanger Studio) — Universal Installer

Installer otomatis untuk membangun mail server modern, aman, dan siap produksi beserta Web Dashboard Manajemen dan Webmail Roundcube. Dirancang khusus untuk kompatibel lintas distribusi Linux: **Keluarga Debian** (*Debian, Ubuntu*) dan **Keluarga RedHat** (*RHEL, AlmaLinux, Rocky Linux, CentOS Stream, Fedora*).

---

## 🌟 Fitur Utama

- **Modern Light Mode Dashboard**: Antarmuka web clean, responsif, dan elegan untuk memantau performa mail server.
- **User Management & 2FA / TOTP**: Hak akses multi-admin dan otentikasi dua faktor berbasis aplikasi authenticator (Google Authenticator, Microsoft Authenticator, 1Password).
- **MTA Postfix & Dovecot**: Mendukung protokol modern IMAP (993), POP3 (995), SMTP Submission (587 STARTTLS), dan SMTPS (465 SSL).
- **Roundcube Webmail**: Dilengkapi plugin Elastic skin, ManageSieve (auto junk sorting), archive, dan zip download.
- **Anti-Spam & Keamanan Rspamd + Redis**: Milter filter, reputasi pengirim, blokir ekstensi file berbahaya (.exe, .bat, .vbs), dan subject blacklist.
- **DKIM & ARC Signing Otomatis**: Kunci kriptografi dibuat dan dipasang otomatis untuk setiap domain.
- **Panduan DNS Terintegrasi**: Rekomendasi siap salin untuk DKIM, DMARC (Quarantine, Reject, Monitor), SPF dengan format eksplisit `+mx +ip4:<IP> ~all`, dan MX record.
- **Riwayat Transaksi Email 30 Hari**: Logging transaksi masuk/keluar, pelacakan status (`DELIVERED`, `SENT`, `REJECTED`, `SPAM`), dan arsip kompresi `.json.gz` otomatis.
- **CLI Helper `emxs`**: Perintah manajemen cepat (`emxs status`, `emxs restart`, `emxs certbot`, `emxs reset-admin`, `emxs logs`).

---

## 🐧 Kompatibilitas Sistem Operasi

| Keluarga OS | Distribusi Linux yang Didukung | Package Manager |
|---|---|---|
| **Debian** | Ubuntu 20.04 LTS, 22.04 LTS, 24.04 LTS | `apt-get` |
| **Debian** | Debian 11 (Bullseye), Debian 12 (Bookworm) | `apt-get` |
| **RedHat** | AlmaLinux 8, AlmaLinux 9 | `dnf` |
| **RedHat** | Rocky Linux 8, Rocky Linux 9 | `dnf` |
| **RedHat** | RHEL (Red Hat Enterprise Linux) 8, 9 | `dnf` |
| **RedHat** | CentOS Stream 8, 9 | `dnf` |
| **RedHat** | Fedora 38, 39, 40+ | `dnf` |

---

## 📋 Prasyarat Server

1. **Akses Root**: VPS atau dedicated server bersih (clean install) dengan akses `root` atau `sudo`.
2. **RAM & CPU**: Minimum 1 GB RAM (Disarankan 2 GB+ untuk performa Rspamd yang optimal) dan 1 vCPU.
3. **Port Terbuka**: Pastikan provider cloud Anda tidak memblokir port outbound 25 (SMTP).
4. **Hostname FQDN**: Disarankan mengatur hostname server terlebih dahulu (contoh: `mail.domainanda.com`).

---

## 🚀 Panduan Instalasi Cepat

### Cara 1: Instalasi Interaktif (Wizard)
Jalankan skrip installer, Anda akan dipandu dengan pertanyaan konfigurasi yang memiliki nilai default pintar:

```bash
cd /root/emxs-installer
chmod +x install.sh
sudo ./install.sh
```

### Cara 2: Instalasi Otomatis (Non-Interactive / Silent)
Cocok untuk otomatisasi skrip deployment (Cloud-Init, Ansible, dsb.):

```bash
sudo ./install.sh \
  --hostname mail.domainanda.com \
  --domain domainanda.com \
  --ip 103.147.157.37 \
  --admin-user admin \
  --admin-email admin@domainanda.com \
  --admin-pass "SandiRahasia2026!Sec" \
  --ssl letsencrypt \
  --non-interactive
```

---

## ⚙️ Opsi Parameter Installer

| Flag | Deskripsi | Default |
|---|---|---|
| `--hostname <FQDN>` | Hostname mail server | Hostname server saat ini |
| `--domain <DOMAIN>` | Domain email utama | Domain yang diturunkan dari FQDN |
| `--ip <IP>` | Alamat IP publik server | Otomatis dideteksi |
| `--admin-user <NAME>` | Username superadmin dashboard | `admin` |
| `--admin-email <EMAIL>` | Email superadmin dashboard | `admin@<domain>` |
| `--admin-pass <PASS>` | Password superadmin dashboard | Dibuat acak 16 karakter |
| `--db-pass <PASS>` | Password user PostgreSQL `mailuser` | Dibuat acak 16 karakter |
| `--rc-db-pass <PASS>` | Password user PostgreSQL `roundcube` | Dibuat acak 16 karakter |
| `--ssl <MODE>` | Mode SSL (`letsencrypt` atau `selfsigned`) | `letsencrypt` |
| `-y`, `--non-interactive` | Menjalankan instalasi tanpa konfirmasi | `false` |

---

## 🌐 Pengaturan DNS di Domain Provider Anda

Setelah instalasi selesai, pasang record DNS berikut di DNS Manager (Cloudflare, cPanel, atau registrar domain Anda):

| Tipe Record | Host / Name | Value / Target | Keterangan |
|---|---|---|---|
| **A** | `mail` | `103.147.157.37` | Arahkan ke IP publik server |
| **MX** | `@` | `mail.domainanda.com` | Priority: `10` |
| **TXT** | `@` | `v=spf1 +mx +ip4:103.147.157.37 ~all` | SPF Record (tambahkan `+ip4:IP_LAIN` jika ada server lain) |
| **TXT** | `_dmarc` | `v=DMARC1; p=quarantine; rua=mailto:admin@domainanda.com; sp=quarantine; aspf=r;` | Kebijakan proteksi email anti-spoofing |
| **TXT** | `mail._domainkey` | *(Salin dari Dashboard menu Domains / DKIM)* | Tanda tangan kriptografi DKIM |

---

## 🛠️ Perintah CLI Manajemen (`emxs`)

Installer secara otomatis menyertakan utilitas baris perintah `/usr/local/bin/emxs`:

```bash
# 1. Cek kesehatan semua komponen dan port aktif
emxs status

# 2. Restart seluruh layanan mail server secara berurutan
emxs restart

# 3. Terbitkan atau perbarui sertifikat SSL Let's Encrypt
emxs certbot mail.domainanda.com admin@domainanda.com

# 4. Reset kata sandi administrator dashboard
emxs reset-admin admin

# 5. Tampilkan bukti instalasi dan kredensial akses
emxs info

# 6. Pantau streaming log realtime (Postfix, Dovecot, mail-api)
emxs logs
```

---

## 📂 Struktur Direktori Installer

```
emxs-installer/
├── install.sh                       # Master installer untuk Debian & RedHat
├── uninstall.sh                     # Skrip pembersihan / uninstaller
├── emxs.sh                          # Utilitas CLI manajemen (dipasang ke /usr/local/bin/emxs)
├── emxs.service                     # Template Systemd service untuk mail-api
├── emxs.env.example                 # Template file konfigurasi lingkungan /etc/emxs/emxs.env
├── README.md                        # Dokumentasi resmi ini
├── sql/
│   └── init_mailserver.sql          # Skema database PostgreSQL
├── templates/
│   ├── postfix/                     # Template main.cf, master.cf, dan pgsql maps
│   ├── dovecot/                     # Template dovecot-sql, 10-mail, 10-auth, 10-master, sieve
│   ├── rspamd/                      # Template milter_headers, arc, dkim, multimap, actions, maps
│   ├── roundcube/                   # Template config.inc.php dan managesieve
│   └── nginx/                       # Template listener lokal Roundcube
└── src/
    └── mail-api/                    # Source code Go dari EMXS Management API & Dashboard
        ├── go.mod
        ├── go.sum
        └── main.go
```

---

## 🗑️ Cara Mencopot Pemasangan (Uninstall)

Jika Anda ingin membersihkan server atau memasang ulang:

```bash
sudo ./uninstall.sh
```
Skrip uninstaller akan menanyakan apakah Anda ingin membuat arsip cadangan (backup) database dan kotak surat `/var/mail/vhosts` sebelum proses pembersihan dilakukan.
