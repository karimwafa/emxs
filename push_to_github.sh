#!/usr/bin/env bash
set -e
cd /root/emxs-installer

export GIT_SSH_COMMAND="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i /root/.ssh/id_ed25519"

echo "--> Menyelaraskan source code & assets..."
mkdir -p src/mail-api assets/icons
cp -rf /root/mail-api/* src/mail-api/
cp -rf /var/www/emxs_icons/* assets/icons/ 2>/dev/null || true

echo "--> Menyiapkan Git repository..."
git init
git config user.name "karimwafa"
git config user.email "admin@elsw-studio.my.id"
git branch -M main

git remote remove origin 2>/dev/null || true
git remote add origin git@github.com:karimwafa/emxs.git

echo "--> Menarik (pull) commit awal jika ada di remote..."
git pull origin main --rebase --allow-unrelated-histories 2>/dev/null || true

echo "--> Menambahkan semua file installer..."
git add -A
git commit -m "feat: Add universal EMXS mail server installer for Debian and RedHat families" || true

echo "--> Melakukan push ke github.com/karimwafa/emxs..."
git push -u origin main

echo "SUCCESS_PUSH"
