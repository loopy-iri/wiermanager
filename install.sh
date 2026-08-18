#!/bin/sh
set -eu
test "$(id -u)" = 0 || { echo "run as root"; exit 1; }
apt-get update
apt-get install -y python3 python3-venv wireguard-tools ca-certificates wget
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
install -d -m 0755 /opt/wiremanager /var/lib/wiremanager /etc/wiremanager/proxy
cp -a . /opt/wiremanager/
python3 -m venv /opt/wiremanager/.venv
/opt/wiremanager/.venv/bin/pip install --no-cache-dir -r /opt/wiremanager/requirements.txt
install -m 0644 deploy/wiremanager.service /etc/systemd/system/
install -m 0644 deploy/wiremanager-proxy@.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now wiremanager.service
echo "WireManager listening on http://127.0.0.1:8080"
