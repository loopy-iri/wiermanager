#!/bin/sh
set -eu
test "$(id -u)" = 0 || { echo "run as root"; exit 1; }
port="${WIREMANAGER_PORT:-}"
while :; do
  if [ -z "$port" ]; then
    printf "API port [8080]: "
    read -r port
    port="${port:-8080}"
  fi
  case "$port" in
    ''|*[!0-9]*) echo "enter a number between 1024 and 65535"; port="" ;;
    *) [ "$port" -ge 1024 ] && [ "$port" -le 65535 ] && break || { echo "enter a number between 1024 and 65535"; port=""; } ;;
  esac
done
apt-get update
apt-get install -y python3 python3-venv wireguard-tools systemd-resolved ca-certificates wget
systemctl enable --now systemd-resolved.service
if apt-cache show 3proxy >/dev/null 2>&1; then
  apt-get install -y 3proxy
else
  arch="$(dpkg --print-architecture)"
  case "$arch" in
    amd64) asset_arch="x86_64" ;;
    arm64) asset_arch="arm64" ;;
    armhf) asset_arch="arm" ;;
    *) echo "unsupported architecture for 3proxy: $arch"; exit 1 ;;
  esac
  version="0.9.6"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  wget -q --show-progress -O "$tmp/3proxy.deb" \
    "https://github.com/3proxy/3proxy/releases/download/$version/3proxy-$version.$asset_arch.deb"
  dpkg -i "$tmp/3proxy.deb" || apt-get -f install -y
fi
systemctl disable --now 3proxy.service 2>/dev/null || true
install -d -m 0755 /opt/wiremanager /var/lib/wiremanager /etc/wiremanager/proxy
printf 'WIREMANAGER_PORT=%s\n' "$port" > /etc/wiremanager/wiremanager.env
chmod 0644 /etc/wiremanager/wiremanager.env
cp -a . /opt/wiremanager/
python3 -m venv /opt/wiremanager/.venv
/opt/wiremanager/.venv/bin/pip install --no-cache-dir -r /opt/wiremanager/requirements.txt
install -m 0644 deploy/wiremanager.service /etc/systemd/system/
install -m 0644 deploy/wiremanager-proxy@.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable wiremanager.service
systemctl restart wiremanager.service
echo "WireManager listening on http://127.0.0.1:$port"
