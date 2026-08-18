# WireManager

Minimal FastAPI service for named WireGuard profiles and one 3proxy instance per profile.

## Install

Run on a Debian/Ubuntu Linux server as root:

```sh
git clone https://github.com/loopy-iri/wiermanager.git && cd wiermanager && sh install.sh
```

<!-- GitHub one-line install: git clone https://github.com/loopy-iri/wiermanager.git && cd wiermanager && sudo sh install.sh -->

Put a reverse proxy/authentication layer in front of `127.0.0.1:8080` before exposing it.

## Project structure

```text
app/main.py                 FastAPI API, SQLite schema, validation, runner
static/index.html           dependency-free web UI
deploy/wiremanager.service  API systemd unit
deploy/wiremanager-proxy@.service  one templated 3proxy unit per profile
install.sh                  Debian/Ubuntu installer
```

## SQLite schema

```sql
CREATE TABLE profiles (
  name TEXT PRIMARY KEY, config_path TEXT UNIQUE NOT NULL,
  interface_name TEXT UNIQUE NOT NULL, proxy_port INTEGER UNIQUE NOT NULL,
  status TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
```

## API design

`POST /profiles` (multipart fields `name`, `config`), `GET /profiles`, `POST /profiles/{name}/{connect|disconnect|restart}`, `DELETE /profiles/{name}`, and `GET /profiles/{name}/status`.

Profile responses contain `name`, `config_path`, `interface_name`, `proxy_port`, `status`, `created_at`, and `updated_at`. Status additionally reports `wireguard` and `proxy` as `up`/`down`; combined status is `connected`, `partial`, or `disconnected`.

The runner only executes fixed commands (`wg-quick`, `wg`, `systemctl`) with argument arrays. Names are restricted, configs are size/section/key validated, files are mode `0600`, ports are allocated from `10000-20000`, and SQLite uniqueness prevents collisions.

## Service runner design

Each profile is saved as `/etc/wireguard/{name}.conf`; `wg-quick` therefore uses the name itself as the interface (limited to Linux's 15-character limit). It also gets `/etc/wiremanager/proxy/{name}.cfg` plus `wiremanager-proxy@{name}.service`. Connect runs `wg-quick up` and starts the proxy; disconnect stops both; restart cycles both. Deleting stops services before removing files and metadata.

## Deployment steps

1. Install Debian/Ubuntu and ensure the host has a valid WireGuard kernel/module and a reachable upstream network.
2. Run `sudo sh install.sh`; it asks for the API port (default `8080`) and installs Python, WireGuard tools, 3proxy, the venv, and both systemd units.
3. Put an authentication/TLS reverse proxy in front of `127.0.0.1:8080` (or use an SSH tunnel). Do not expose the root-owned API directly.
4. Check `journalctl -u wiremanager.service` and `systemctl status wiremanager-proxy@NAME` for operations.

## UI flow

Open the service URL, upload a `.conf` with a name, then use Connect/Disconnect/Restart/Delete. Each row shows WireGuard state, proxy state and port.
