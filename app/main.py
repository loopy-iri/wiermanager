from __future__ import annotations

import os
import re
import socket
import sqlite3
import subprocess
import logging
import ipaddress
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel

DB_PATH = Path(os.getenv("WIREMANAGER_DB", "/var/lib/wiremanager/wiremanager.db"))
WG_DIR = Path(os.getenv("WIREMANAGER_WG_DIR", "/etc/wireguard"))
PROXY_DIR = Path(os.getenv("WIREMANAGER_PROXY_DIR", "/etc/wiremanager/proxy"))
PROXY_SERVICE = os.getenv("WIREMANAGER_PROXY_SERVICE", "wiremanager-proxy@")
PORT_MIN = int(os.getenv("WIREMANAGER_PROXY_PORT_MIN", "10000"))
PORT_MAX = int(os.getenv("WIREMANAGER_PROXY_PORT_MAX", "20000"))
NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,14}$")
ops_lock = Lock()
logging.basicConfig(level=os.getenv("WIREMANAGER_LOG_LEVEL", "INFO"))
log = logging.getLogger("wiremanager")

app = FastAPI(title="WireManager", version="1.0")


class Profile(BaseModel):
    name: str
    config_path: str
    interface_name: str
    proxy_port: int
    status: str
    created_at: str
    updated_at: str


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """CREATE TABLE IF NOT EXISTS profiles (
        name TEXT PRIMARY KEY,
        config_path TEXT NOT NULL UNIQUE,
        interface_name TEXT NOT NULL UNIQUE,
        proxy_port INTEGER NOT NULL UNIQUE,
        status TEXT NOT NULL DEFAULT 'disconnected',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
        )"""
    )
    return conn


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    log.info("running %s", " ".join(args[:2]))
    try:
        return subprocess.run(list(args), check=check, capture_output=True, text=True, timeout=30)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as exc:
        detail = (getattr(exc, "stderr", "") or str(exc) or "command failed").strip().replace("\n", " ")
        log.error("command failed: %s", detail.strip())
        raise HTTPException(502, f"{args[0]} failed: {detail[:300]}") from exc


def prepare_config(raw: bytes, table: int) -> tuple[str, str]:
    if len(raw) > 1024 * 1024:
        raise HTTPException(400, "config is too large")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(400, "config must be UTF-8") from exc
    sections = {line.strip().lower() for line in text.splitlines() if line.strip().startswith("[") and line.strip().endswith("]")}
    if "[interface]" not in sections or "[peer]" not in sections:
        raise HTTPException(400, "config must contain [Interface] and [Peer]")
    if not re.search(r"(?im)^\s*privatekey\s*=\s*\S+", text):
        raise HTTPException(400, "config is missing PrivateKey")
    if not re.search(r"(?im)^\s*publickey\s*=\s*\S+", text):
        raise HTTPException(400, "config is missing Peer PublicKey")
    cleaned, section, address = [], "", None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped.lower()
        key = stripped.split("=", 1)[0].strip().lower() if "=" in stripped else ""
        if key in {"preup", "postup", "predown", "postdown", "saveconfig", "table", "dns"}:
            continue
        if section == "[interface]" and key == "address":
            for value in stripped.split("=", 1)[1].split(","):
                try:
                    candidate = ipaddress.ip_interface(value.strip())
                except ValueError as exc:
                    raise HTTPException(400, "config has an invalid Address") from exc
                if candidate.version == 4:
                    address = str(candidate.ip)
                    break
        cleaned.append(line)
    if not address:
        raise HTTPException(400, "config needs an IPv4 Address in [Interface]")
    peer_at = next((i for i, line in enumerate(cleaned) if line.strip().lower() == "[peer]"), None)
    if peer_at is None:
        raise HTTPException(400, "config must contain [Peer]")
    routes = [
        "Table = off",
        f"PostUp = ip rule del from {address}/32 table {table} priority {table} || true; ip rule add from {address}/32 table {table} priority {table}",
        f"PostUp = ip route replace default dev %i table {table}",
        f"PostDown = ip rule del from {address}/32 table {table} priority {table} || true",
        f"PostDown = ip route del default dev %i table {table} || true",
    ]
    return "\n".join(cleaned[:peer_at] + routes + cleaned[peer_at:]) + "\n", address


def interface_for(name: str) -> str:
    # wg-quick derives the interface name from the config basename.
    return name


def free_port() -> int:
    used = {row[0] for row in db().execute("SELECT proxy_port FROM profiles")}
    for port in range(PORT_MIN, PORT_MAX + 1):
        if port in used:
            continue
        with socket.socket() as sock:
            try:
                sock.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise HTTPException(507, "no proxy ports available")


def row_payload(row: sqlite3.Row) -> dict:
    item = dict(row)
    item["status"] = profile_status(item["name"], item["interface_name"], item["proxy_port"])["status"]
    return item


def profile_status(name: str, interface: str, port: int) -> dict:
    wg_up = run("wg", "show", interface, check=False).returncode == 0
    proxy = run("systemctl", "is-active", f"{PROXY_SERVICE}{name}.service", check=False)
    proxy_up = proxy.returncode == 0 and proxy.stdout.strip() == "active"
    status = "connected" if wg_up and proxy_up else "partial" if wg_up or proxy_up else "disconnected"
    return {"name": name, "interface_name": interface, "proxy_port": port, "wireguard": "up" if wg_up else "down", "proxy": "up" if proxy_up else "down", "status": status}


def get_profile(name: str) -> sqlite3.Row:
    row = db().execute("SELECT * FROM profiles WHERE name=?", (name,)).fetchone()
    if not row:
        raise HTTPException(404, "profile not found")
    return row


def proxy_config(name: str, port: int, external_ip: str) -> Path:
    PROXY_DIR.mkdir(parents=True, exist_ok=True)
    path = PROXY_DIR / f"{name}.cfg"
    path.write_text(f"nscache 65536\nauth none\nallow *\nproxy -p{port} -e{external_ip}\n", encoding="ascii")
    path.chmod(0o600)
    return path


@app.on_event("startup")
def startup() -> None:
    db().close()
    WG_DIR.mkdir(parents=True, exist_ok=True)
    PROXY_DIR.mkdir(parents=True, exist_ok=True)


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(Path(__file__).parent.parent / "static" / "index.html")


@app.post("/profiles", response_model=Profile, status_code=201)
async def create_profile(name: str = Form(...), config: UploadFile = File(...)):
    if not NAME_RE.fullmatch(name):
        raise HTTPException(400, "name must be 1-15 chars: letters, digits, _ or -")
    raw = await config.read()
    with ops_lock, db() as conn:
        if conn.execute("SELECT 1 FROM profiles WHERE name=?", (name,)).fetchone():
            raise HTTPException(409, "profile name already exists")
        interface = interface_for(name)
        if conn.execute("SELECT 1 FROM profiles WHERE interface_name=?", (interface,)).fetchone():
            raise HTTPException(409, "profile maps to an existing interface")
        port = free_port()
        text, external_ip = prepare_config(raw, port)
        path = WG_DIR / f"{name}.conf"
        if path.exists():
            raise HTTPException(409, "config path already exists")
        path.write_text(text, encoding="utf-8")
        path.chmod(0o600)
        proxy_config(name, port, external_ip)
        stamp = now()
        conn.execute("INSERT INTO profiles VALUES (?,?,?,?,?,?,?)", (name, str(path), interface, port, "disconnected", stamp, stamp))
        return row_payload(conn.execute("SELECT * FROM profiles WHERE name=?", (name,)).fetchone())


@app.get("/profiles")
def list_profiles():
    conn = db()
    return [profile_status(row["name"], row["interface_name"], row["proxy_port"]) | row_payload(row) for row in conn.execute("SELECT * FROM profiles ORDER BY name")]


def change(name: str, action: str):
    with ops_lock, db() as conn:
        row = get_profile(name)
        if action == "connect":
            text, external_ip = prepare_config(Path(row["config_path"]).read_bytes(), row["proxy_port"])
            Path(row["config_path"]).write_text(text, encoding="utf-8")
            proxy_config(name, row["proxy_port"], external_ip)
            run("wg-quick", "up", row["config_path"])
            run("systemctl", "enable", "--now", f"{PROXY_SERVICE}{name}.service")
        elif action == "disconnect":
            run("systemctl", "disable", "--now", f"{PROXY_SERVICE}{name}.service", check=False)
            run("wg-quick", "down", row["config_path"], check=False)
        else:
            run("systemctl", "restart", f"{PROXY_SERVICE}{name}.service")
            run("wg-quick", "down", row["config_path"], check=False)
            run("wg-quick", "up", row["config_path"])
        stamp = now()
        conn.execute("UPDATE profiles SET status=?, updated_at=? WHERE name=?", (profile_status(name, row["interface_name"], row["proxy_port"])["status"], stamp, name))
        return profile_status(name, row["interface_name"], row["proxy_port"])


@app.post("/profiles/{name}/connect")
def connect(name: str):
    return change(name, "connect")


@app.post("/profiles/{name}/disconnect")
def disconnect(name: str):
    return change(name, "disconnect")


@app.post("/profiles/{name}/restart")
def restart(name: str):
    return change(name, "restart")


@app.delete("/profiles/{name}")
def delete_profile(name: str):
    with ops_lock, db() as conn:
        row = get_profile(name)
        run("systemctl", "disable", "--now", f"{PROXY_SERVICE}{name}.service", check=False)
        run("wg-quick", "down", row["config_path"], check=False)
        Path(row["config_path"]).unlink(missing_ok=True)
        (PROXY_DIR / f"{name}.cfg").unlink(missing_ok=True)
        conn.execute("DELETE FROM profiles WHERE name=?", (name,))
    return {"deleted": name}


@app.get("/profiles/{name}/status")
def status(name: str):
    row = get_profile(name)
    return profile_status(name, row["interface_name"], row["proxy_port"])


if __name__ == "__main__":
    assert interface_for("home-vpn") == "home-vpn"
    config, ip = prepare_config(b"[Interface]\nPrivateKey = x\nAddress = 10.0.0.2/24\n[Peer]\nPublicKey = y\n", 10000)
    assert ip == "10.0.0.2" and "Table = off" in config
    print("self-check passed")
