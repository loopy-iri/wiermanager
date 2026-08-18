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
apt-get install -y python3 python3-venv wireguard-tools ca-certificates wget build-essential
if apt-cache policy 3proxy 2>/dev/null | awk '$1 == "Candidate:" && $2 != "(none)" { found=1 } END { exit !found }'; then
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
proxy_bin="$(command -v 3proxy 2>/dev/null || true)"
if [ ! -f "$proxy_bin" ] || [ ! -x "$proxy_bin" ]; then
  proxy_bin="$(dpkg -L 3proxy 2>/dev/null | while read -r candidate; do
    if [ -f "$candidate" ] && [ -x "$candidate" ]; then
      echo "$candidate"
      break
    fi
  done)"
fi
if [ ! -f "$proxy_bin" ] || [ ! -x "$proxy_bin" ]; then
  src="$(mktemp -d)"
  trap 'rm -rf "$src"' EXIT
  wget -q --show-progress -O "$src/3proxy.tgz" \
    "https://github.com/3proxy/3proxy/archive/refs/tags/0.9.6.tar.gz"
  tar -xzf "$src/3proxy.tgz" -C "$src"
  build_dir="$(find "$src" -mindepth 1 -maxdepth 1 -type d -name '3proxy-*' -print -quit)"
  (cd "$build_dir" && ln -sf Makefile.Linux Makefile && make)
  install -m 0755 "$build_dir/bin/3proxy" /usr/local/bin/3proxy
  proxy_bin=/usr/local/bin/3proxy
fi
sed -i "s|@3PROXY_BIN@|$proxy_bin|g" /etc/systemd/system/wiremanager-proxy@.service
systemctl daemon-reload
systemctl enable wiremanager.service
systemctl restart wiremanager.service
echo "WireManager listening on http://127.0.0.1:$port"
