#!/bin/sh
set -eu
test "$(id -u)" = 0 || { echo "run as root"; exit 1; }
apt-get update
apt-get install -y python3 python3-venv wireguard-tools 3proxy
install -d -m 0755 /opt/wiremanager /var/lib/wiremanager /etc/wiremanager/proxy
cp -a . /opt/wiremanager/
python3 -m venv /opt/wiremanager/.venv
/opt/wiremanager/.venv/bin/pip install --no-cache-dir -r /opt/wiremanager/requirements.txt
install -m 0644 deploy/wiremanager.service /etc/systemd/system/
install -m 0644 deploy/wiremanager-proxy@.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now wiremanager.service
echo "WireManager listening on http://127.0.0.1:8080"
