#!/usr/bin/env bash
# ============================================================
#  IoCManager v1.6 - Ubuntu Kurulum Scripti
#  Calistirma:
#    sudo bash kurulum.sh
# ============================================================

set -euo pipefail

APP_DIR="/opt/iocmanager"
FEED_DIR="/opt/threatfeed/public"
SVC_USER="iocmanager"
PORT=5000
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"   # linux/ klasorunun bir ustu = repo koku

step() { echo -e "\033[1;36m[$1/8]\033[0m $2"; }

if [ "$EUID" -ne 0 ]; then
    echo "Bu script root ile calistirilmali: sudo bash kurulum.sh"
    exit 1
fi

echo ""
echo "  ================================"
echo "   IoCManager v1.6 - Ubuntu Kurulum"
echo "  ================================"
echo ""

# 1. Sistem paketleri
step 1 "Sistem paketleri kontrol ediliyor..."
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip ufw >/dev/null

# 2. Servis kullanicisi
step 2 "Servis kullanicisi olusturuluyor..."
if ! id -u "$SVC_USER" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
fi

# 3. Dizinler
step 3 "Dizinler olusturuluyor..."
mkdir -p "$APP_DIR"/{data,logs,templates,static}
mkdir -p "$FEED_DIR"

# 4. Uygulama dosyalari
step 4 "Uygulama dosyalari kopyalaniyor..."
cp "$REPO_ROOT/app.py" "$APP_DIR/app.py"
cp "$REPO_ROOT/run.py" "$APP_DIR/run.py"
cp "$SCRIPT_DIR/requirements-linux.txt" "$APP_DIR/requirements.txt"
cp -r "$REPO_ROOT/templates/." "$APP_DIR/templates/"
[ -d "$REPO_ROOT/static" ] && cp -r "$REPO_ROOT/static/." "$APP_DIR/static/" 2>/dev/null || true

# 5. Python venv + bagimliliklar
step 5 "Python sanal ortami kuruluyor..."
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --upgrade pip -q
"$APP_DIR/venv/bin/pip" install -r "$APP_DIR/requirements.txt" -q

# 6. Izinler
step 6 "Izinler ayarlaniyor..."
chown -R "$SVC_USER":"$SVC_USER" "$APP_DIR"
chown -R "$SVC_USER":"$SVC_USER" "$FEED_DIR"
chmod 750 "$APP_DIR"
chmod 750 "$APP_DIR/data"

# 7. Firewall
step 7 "Firewall kurali ekleniyor (port $PORT)..."
ufw allow "$PORT"/tcp comment "IoCManager" >/dev/null 2>&1 || true

# 8. systemd servisi
step 8 "systemd servisi kuruluyor..."
cp "$SCRIPT_DIR/iocmanager.service" /etc/systemd/system/iocmanager.service
systemctl daemon-reload
systemctl enable iocmanager >/dev/null 2>&1
systemctl restart iocmanager

sleep 3
STATE=$(systemctl is-active iocmanager || true)

echo ""
echo "  ================================"
echo "   Kurulum tamamlandi!"
echo "  ================================"
echo ""
if [ "$STATE" = "active" ]; then
    echo -e "  Servis durumu : \033[1;32m$STATE\033[0m"
else
    echo -e "  Servis durumu : \033[1;33m$STATE\033[0m"
fi
IP=$(hostname -I | awk '{print $1}')
echo "  Portal        : http://$IP:$PORT"
echo "  Lokal test    : http://localhost:$PORT"
echo "  Giris         : admin / IoCManager2026!"
echo -e "  \033[1;31mUYARI: Ilk giriste sifreyi degistirin!\033[0m"
echo ""

if [ "$STATE" != "active" ]; then
    echo "  Servis aktif degil. Loglara bakin:"
    echo "    journalctl -u iocmanager -n 50 --no-pager"
    echo ""
fi
