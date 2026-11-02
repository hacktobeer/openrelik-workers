# OpenRelik Persistence Analyzer Worker (`openrelik-worker-persistence`)

Automated, semantic forensic analysis of system persistence mechanisms on forensic disk images and extracted artifact collections.

## Overview

The Persistence Analyzer Worker parses system configuration files, systemd unit files, task schedules, shell environments, authentication stores, and startup scripts into semantic representations. Rather than relying solely on raw string matching, it flags suspicious behaviors, obfuscation, unprivileged tampering vectors, and **cross-boundary execution configurations** (system-level privileges executing files located in user-controlled or temporary paths).

## Supported Persistence Vectors

- **Systemd Services & Timers**: System (`/etc/systemd/system`, `/lib/systemd/system`) and user scope (`~/.config/systemd/user`).
- **Cron Jobs**: System crontabs (`/etc/crontab`, `/etc/cron.*`, `/etc/anacrontab`) and user spool crontabs (`/var/spool/cron/crontabs`).
- **Shell Profiles & RC Injections**: System-wide (`/etc/profile`, `/etc/bash.bashrc`) and user startup files (`~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.zshrc`).
- **SSH Authorized Keys & Config**: User `authorized_keys`, root keys, forced command restrictions, and `sshd_config` audit.
- **SysV Init & Startup Scripts**: `/etc/rc.local`, `/etc/init.d/`, and `/etc/rc[0-6].d/` runlevel scripts.
- **Dynamic Linker Preloading**: `/etc/ld.so.preload` and `/etc/ld.so.conf.d/`.
- **Sudoers & PAM Authentication**: `NOPASSWD` rules in `/etc/sudoers` targeting user binaries, and custom PAM modules.
- **XDG Desktop Autostart**: System and user `.desktop` autostart entries.
- **Cross-Boundary Analysis**: Flags high-privilege system tasks pointing to binaries or scripts inside user-controlled directories (`/home/*`, `/tmp/*`, `/dev/shm/*`).

## Development & Testing

Run tests and linting using `uv`:

```bash
cd workers/persistence
uv sync
uv run pytest
uv run ruff check
uv run ruff format --check
```

## Docker Deployment

Add to your `docker-compose.yml`:

```yaml
openrelik-worker-persistence:
  container_name: openrelik-worker-persistence
  image: ghcr.io/openrelik/openrelik-worker-persistence:latest
  privileged: true
  restart: always
  environment:
    - REDIS_URL=redis://openrelik-redis:6379
  volumes:
    - ./data:/usr/share/openrelik/data
    - /dev:/dev
  command: "celery --app=src.tasks worker --task-events --concurrency=1 --loglevel=INFO -Q openrelik-worker-persistence"
```
