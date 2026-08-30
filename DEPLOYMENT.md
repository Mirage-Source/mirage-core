# Deploying a sensor from scratch

The README's `docker compose up --build` is accurate but leaves out everything
that only shows up the first time you actually do this on a bare VPS. This is
that missing context, written up after standing up the Nuremberg sensor
(see `DECISIONS.md`).

---

## 0. Before you touch Docker: move real SSH off port 22

`docker-compose.yml` maps the honeypot's fake SSH to the **host's** port 22
(`"22:2222"`). If your admin sshd is still listening there — which it is, on
every fresh VPS — Compose will either fail to bind or, if it somehow starts,
your one real way into the box is now fighting the honeypot for the same port.

Move it first:

```bash
# /etc/ssh/sshd_config
Port 2222      # or whatever you prefer; just not 22
```

Bring the new port up *alongside* the old one, confirm you can log in on it
from a second terminal, then remove `Port 22` and restart sshd again. Don't
remove the old port until you've verified the new one works — an sshd restart
that goes wrong with no fallback port is how you end up needing the netcup
web console's KVM/rescue access to fix it.

There's no firewall active by default on a fresh netcup Debian image (`ufw`
isn't even installed). Set one up while you're in here:

```bash
apt-get install -y ufw
ufw allow 2222/tcp     # your admin ssh port
ufw allow 22/tcp       # the honeypot — deliberately open to the world
ufw allow 80/tcp       # only if you're doing ACME/reverse-proxy TLS for mirage-web
ufw allow 443/tcp      # ditto — skip both if you're using a Cloudflare Tunnel instead
ufw default deny incoming
ufw default allow outgoing
ufw --force enable
```

---

## 1. `.env`: don't leave `POSTGRES_PASSWORD`/`API_KEY` at their defaults

`.env.example` now documents both (previously it silently required
`POSTGRES_PASSWORD` — the exact variable the official Postgres image's
entrypoint checks for on first init — without ever mentioning it, since
`docker-compose.yml`'s `postgres` service doesn't map `DB_PASSWORD` to it for
you; and `API_KEY` wasn't in the file at all despite `mirage-api` requiring
it). Both ship as `changeme` placeholders — replace them for real:

```bash
cp .env.example .env
# then edit DB_PASSWORD, POSTGRES_PASSWORD (keep identical to DB_PASSWORD),
# and API_KEY in .env
openssl rand -hex 32   # good enough for either one
```

---

## 2. Host key: permission denied under the container's non-root user

```bash
./scripts/generate_hostkey.sh
```

writes `config/hostkey` as `600 root:root`. The `mirage-core` image runs as
`USER mirage` (see `Dockerfile`), which can't read a root-only file even
though the compose mount is read-only — read-only affects *writes*, not who's
allowed to open it at all. The container will crash-loop on
`open config/hostkey: permission denied` until you loosen it:

```bash
chmod 644 config/hostkey
```

---

## 3. Schema catch-up: a fresh clone starts behind

`db/init/*.sql` only runs once, automatically, against an *empty* Postgres
data directory — that's a Postgres-image behavior, not a mirage-core choice.
`internal/store/migrations/` holds the incremental patches applied by hand to
the already-running production sensor over time, and **`db/init/` was not kept
fully in sync with them**. A brand-new deploy from a fresh clone will hit
`pq: column "deception_action" does not exist` (and similar) the first time
the data-validity dashboard queries a column that only exists via a
hand-applied migration.

After your first `docker compose up`, catch up in order (all are
idempotent — safe to re-run, safe even if some already applied via `db/init`):

```bash
for f in 003_deception 004_command_response 005_ml_intelligence_catchup \
         007_ingress_source 008_sensor_heartbeats 009_drop_grafana_role; do
  docker compose exec -T postgres psql -U mirage -d mirage \
      < internal/store/migrations/${f}.sql
done
```

Skip `006_grafana_readonly_role.sql` — it creates the Grafana read-only role
that `009` immediately retires (Prometheus/Grafana are retired; see README).
Running `009` alone against a fresh DB that never had `006` applied is an
explicit documented no-op, which is exactly what you want here.

---

## 4. mirage-web

Separate repo, separate runtime (Node, not Docker — see its own
`README.md`/`SETUP.md`). The one thing worth repeating here: it needs
`MIRAGE_API_KEY` in its `.env` to be **the same value** as `API_KEY` in
mirage-core's `.env`, and it has to either run on the same host as
`mirage-api` (which binds `127.0.0.1:8080`, not `0.0.0.0`) or reach it over a
tunnel/SSH port-forward.

A minimal systemd unit for running it as a persistent service outside Docker:

```ini
[Unit]
Description=mirage-web (Next.js dashboard)
After=network.target docker.service

[Service]
Type=simple
WorkingDirectory=/opt/mirage/mirage-web
ExecStart=/usr/bin/npm start
Restart=on-failure
RestartSec=5s
Environment=PORT=3000
User=root

[Install]
WantedBy=multi-user.target
```

`npm run build` before the first start — `npm start` serves the build, it
doesn't create one.

---

## 5. Exposing mirage-web: Cloudflare Tunnel quirk

If you generate the tunnel token from the Zero Trust dashboard's quick-connect
flow (`cloudflared service install <token>`), you get a **locally-managed**
tunnel. The dashboard's Public Hostname UI explicitly refuses to configure
routes for this kind of tunnel ("Routes are configured via the local
configuration file and cannot be modified from the dashboard").

Instead, write `/etc/cloudflared/config.yml` yourself — `cloudflared` loads it
automatically from that default path, no `--config` flag or systemd unit
change needed:

```yaml
ingress:
  - hostname: your.subdomain.here
    service: http://localhost:3000
  - service: http_status:404
```

(Don't add `tunnel:`/`credentials-file:` keys here — those are for
certificate-based auth, not the token-based flow, and can conflict with it.)

Then `systemctl restart cloudflared`. The DNS side is also manual: add a
**CNAME** record for your subdomain pointing at
`<tunnel-id>.cfargotunnel.com` (proxied) in the zone's regular DNS tab — not
the tunnel screen. You can read the tunnel ID back out of the token itself if
you don't have it handy (`token` is base64 JSON: `{"a": account_id, "t":
tunnel_id, "s": secret}`).

---

## 6. A Go API quirk worth remembering when adding new endpoints

Any handler that builds a JSON slice field by `append`-ing to a struct's zero
value will marshal that field as `null`, not `[]`, whenever zero rows match
(a fresh sensor, an empty result set, no coordinated-IP campaign detected
yet). Every frontend consumer needs to either get a real empty slice from the
API or defensively null-guard before calling `.filter()`/`.slice()`/`.map()`
on it — both `GetCommandExport` and `GetStats` were fixed to initialize their
slice fields explicitly rather than leaving them nil; keep that pattern for
anything new.

---

## 7. Re-arming the GitHub Actions workflows on a new instance

`go-tests.yml` and `ml-tests.yml` never depended on a live sensor and need
nothing. The other three do, and every deploy-related secret in the repo
predates whatever box you are standing up now — none of them are reusable as-is.

### The API is not public, and shouldn't become public

`mirage-api` binds `127.0.0.1:8080` and the Cloudflare Tunnel routes only
mirage-web. `update-stats` and `publish-dataset` therefore open a short-lived
SSH port-forward to the sensor for the length of the job
(`.github/actions/sensor-api-tunnel`), and talk to `http://127.0.0.1:18080`.

Generate a key used *only* for that forward — not the deploy key:

```bash
ssh-keygen -t ed25519 -N "" -C "mirage-api-forward" -f ~/.ssh/mirage_api_forward
```

Add the public half to the sensor's `~/.ssh/authorized_keys` pinned so it can
do nothing except open that one forward:

```
no-pty,no-agent-forwarding,no-X11-forwarding,no-user-rc,permitopen="127.0.0.1:8080",command="/bin/false" ssh-ed25519 AAAA... mirage-api-forward
```

`command="/bin/false"` is not bypassed by the workflow: `ssh -N` opens no
session channel, so the forced command never runs. Anyone who steals the key
and tries to get a shell hits `/bin/false` instead.

Pin the host key rather than letting the runner trust first contact:

```bash
ssh-keyscan -p 2222 <sensor-ip>
```

### Secrets to set

| Secret | Value |
| --- | --- |
| `DEPLOY_HOST` | new sensor IP |
| `DEPLOY_PORT` | admin sshd port (2222, per section 0) |
| `DEPLOY_USER` | user for `deploy.yml`'s shell access |
| `DEPLOY_KEY` | full-shell deploy key, `deploy.yml` only |
| `SENSOR_API_USER` | user owning the restricted forward key |
| `SENSOR_API_KEY_SSH` | private half of `mirage_api_forward` |
| `SENSOR_KNOWN_HOSTS` | the `ssh-keyscan` output above |
| `API_KEY` | must equal `API_KEY` in the sensor's `.env` |
| `IP_SALT` | HMAC salt for the commands export |

`API_URL` is no longer read by anything and can be deleted.

### Dataset versioning across sensors

`publish-dataset.yml` carries `SENSOR_GENERATION` (`g2` for Nuremberg) and
names versions `g2-v1`, `g2-v2`, …, numbering within the generation only. The
Frankfurt series (`v1`…`v6`) stays where it is and is never appended to, and
`export_dataset.py --sensor-generation` stamps the same identifier into
`stats_summary.json`. Bump it when the sensor is replaced again.

### deploy.yml stays manual

Left on `workflow_dispatch` deliberately. The script targets
`/opt/mirage/mirage-core`, which is where the Nuremberg clone lives; check that
first if the checkout ever moves. The remaining gap is that the migration
catch-up in section 3 is still manual — the deploy script does not run it, so a
rebuild onto a fresh volume can come up schema-behind.
