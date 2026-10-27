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

The script now also writes `config/hostkey_rsa` and `config/hostkey_ecdsa`
(already `644`), since a real Ubuntu sshd offers RSA, ECDSA and ed25519 host
keys. It is safe to re-run on an existing deployment: present keys are kept.
If compose started before they existed, it will have created empty
directories at those paths; the script removes them before writing.

---

## 2a. `fleet_queue` volume: same non-root-user problem, for the local retry queue

The same class of bug as the hostkey issue above, hit for real on the
Nuremberg sensor once `MIRAGE_FLEET_URL`/`MIRAGE_FLEET_API_KEY` were actually
turned on: Docker creates a brand-new named volume owned by `root:root`, but
`mirage-core` writes to `MIRAGE_FLEET_QUEUE_PATH` (`/app/data/...` by
default) as `USER mirage` (uid 999). Unlike the hostkey (a read), this is a
write, so the fix isn't a chmod on a host-side file — there's no host-side
file, it's a volume. A fresh clone building the image no longer hits this at
all (the `Dockerfile` now `mkdir`s and `chown`s `/app/data` before `USER
mirage`, so a *new* volume gets that ownership copied in on first creation).

If you're fixing an **already-existing** volume from before that Dockerfile
fix (as the Nuremberg deploy needed), a straight `docker exec -u root
<container> chown ...` doesn't require anything special, but if your
environment restricts root-exec into a running container, a disposable
helper container mounting the same volume works too and needs no elevated
exec at all:

```bash
docker run --rm -v mirage-core_fleet_queue:/data alpine chown -R 999:999 /data
```

Symptom if you miss this: sessions saved locally exactly as normal (this
never touches the honeypot's core save path), but any fleet push that fails
also fails to fall into the local retry queue —
`fleet: queuing session ... also failed: opening queue file: ... permission
denied` in the logs. That's a silent hole in the "no data loss" guarantee
the queue exists for, not a crash, so it's easy to miss until you're
specifically looking for it.

---

## 3. Schema migrations

Every Go binary (`mirage-core`, `mirage-telnet`, `mirage-api`) applies
`internal/store/migrations/*.sql` at startup, through `store.Connect`. Each
file runs once in its own transaction and is recorded in `schema_migrations`;
a Postgres advisory lock keeps services that start together from racing. A
fresh volume and an existing deployment both just need `docker compose up`.
The "apply by hand" notes inside older migration files predate this.

On a database that predates `schema_migrations`, the first start re-runs every
file. They are all idempotent, so this only fills in what is missing.

---

## 3b. Build stamp (`build_sha`, schema_version 1.2)

Every session row records the commit its sensor binary was built from, because
`node_id` (the emulated OS) and `schema_version` cannot tell builds apart.
Deploy the sensors with the stamp:

```sh
BUILD_SHA=$(sh scripts/build_sha.sh) docker compose up -d --build mirage-core mirage-telnet
```

`scripts/build_sha.sh` prints the short sha, with `-dirty` if the tree differs
from HEAD in any way (untracked files count, because `COPY . .` copies them).
If `BUILD_SHA` is not set the image builds, runs, and writes `unknown`; the
sensor logs `build=...` on startup, so `docker compose logs mirage-core | head`
shows what is running. Rows written before this change keep `build_sha = ''`.

Also from schema 1.2: `server_port` is recorded before the handshake, so it is the
same on every SSH session (2222). Before, it was 0 on exactly the `auth_failed`
sessions, which leaked the outcome into a feature. It is the listener's own port, the
container's internal one, not the port the client dialed; that is `target_port`, set
only behind a PROXY-protocol relay and NULL otherwise.
Start a sensor (which applies migration 019) before running `dataset-export`,
which now selects the column.

---

## 3c. Daily health check

`scripts/daily_health_check.py` needs only `python3` and `psql`, and exits 1 on any
finding, so it can run from cron or CI.

```sh
DATABASE_URL=postgresql://... python3 scripts/daily_health_check.py --protocol ssh --check-builds
DATABASE_URL=postgresql://... python3 scripts/daily_health_check.py --protocol telnet
```

| Check | Finds | Why not a rate alone |
|---|---|---|
| accepted pairs | any accepted `user:pass` not on the sensor's accept list (`WEAK_CREDENTIALS_FILE`, `TELNET_WEAK_CREDENTIALS_FILE`) | catches accept-everything at any traffic level; Telnet's ~68% acceptance is policy |
| heartbeats | a silence over 5 min on any sensor, or a latest heartbeat over 5 min old | a 2 h 34 min outage inside a busy day leaves the daily count looking normal |
| hour coverage | a run of hours with no sessions that is unprecedented for the sensor (the quietest 5% of last week's hours had 5 or more) | a capture failure leaves the sensor up and beating (60 heartbeats, no sessions, seen once), and a database without a heartbeat table has no other outage detector |
| build stamp (`--check-builds`) | `build_sha` of `unknown` (deployed without `BUILD_SHA`) or `''` (a pre-1.2 binary) | |
| daily volume and acceptance rate | no-session days; a volume drop below 25% of the trailing median unless every hour of the day had sessions (then only below 5%); SSH acceptance under 1% or over 25% | |

A missing accept list or an unreadable table is reported as a finding, never skipped.

The defaults come from measurement on the two sensors so far: 123,650 heartbeat
intervals had a median of 60.0 s and a largest normal value of 64.6 s, while the
shortest real outage was 16 min; normal SSH days accepted 2.3% to 11.4%, reject-
everything is 0% and accept-everything 61.6% to 100%; Telnet hours are bursty (17%
under 10 sessions), which is why an empty hour is judged against the quietest 5% of
the previous week and not against the median. A third sensor with different traffic
may need `--max-gap-min`, `--max-age-min`, `--min-accept`, `--max-accept` or
`--hour-floor`. Use `--check-builds` only once the sensors have been redeployed with
schema 1.2. Where it runs and how it notifies are not decided here.

---

## 3a. Telnet sensor (`mirage-telnet`, port 23)

Order matters on an existing deployment:

1. Start any updated Go service first so migrations create `telnet_session_meta`.
2. Rebuild `mirage-api` and `ml-worker`, which now filter `protocol = 'ssh'`.
   An old `ml-worker` would try to enrich telnet sessions.
3. Open 23/tcp in the host firewall, then `docker compose up -d --build mirage-telnet`.

Telnet sessions are stored with `protocol = 'telnet'` and `ssh_client_banner = ''`.
The dashboard, exports, validity checks, ML bridge and re-ID stay SSH-only.
Fleet push is off for telnet (`mirage-fleet` has no protocol column), and
the deception policy never runs on it. Accepted logins come from
`config/telnet_weak_credentials.txt` (Mirai's default table, override with
`TELNET_WEAK_CREDENTIALS_FILE`), separate from the SSH list.
A telnet session may run 4,000 commands (SSH: 500) so echo-loaders can
finish writing a payload; `TELNET_MAX_CONCURRENT_CONNECTIONS` (default 100)
keeps that inside the container's 512M limit.
Clients that speak another protocol to port 23 (HTTP, SIP, RTSP, TLS, SSH)
get the normal login dialogue, but their lines are not stored as auth
attempts: the session is saved with `outcome = 'protocol_mismatch'` and the
first line in `telnet_session_meta.foreign_protocol_line`.

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

## 8. Dataset export to R2 (`dataset-export`, `deploy/dataset-export/`)

The dataset is published from the sensor itself: a daily systemd timer runs
`scripts/export_parquet.py` in the `dataset-export` container, which reads
Postgres directly (read-only) and uploads each complete ISO week as
`sessions/protocol=<p>/week=<YYYY-Www>.parquet` and
`commands/protocol=<p>/week=<YYYY-Www>.parquet`, plus `manifest.json`, to a
Cloudflare R2 bucket. Only weeks missing from the manifest are read, so the
load per run is one week, not the whole history. GitHub Actions is not
involved.

One-time setup:

1. In Cloudflare: R2 → create bucket `mirage-dataset`. Under the bucket's
   Settings, enable public access (the `r2.dev` URL, or a custom domain such
   as `data.<your domain>`). Then R2 → Manage API tokens → create a token with
   **Object Read & Write** scoped to that bucket only. Note the account ID,
   access key ID and secret.
2. On the sensor, put `R2_ACCOUNT_ID`, `R2_ACCESS_KEY_ID`,
   `R2_SECRET_ACCESS_KEY`, `R2_BUCKET` and `IP_SALT` in
   `/opt/mirage/mirage-core/.env.export`, **not** `.env` (`chmod 600`). Every
   service loads `.env`, including the internet-facing SSH and telnet
   sensors; only `dataset-export` loads `.env.export`. A compromised sensor
   must never hold a key that can overwrite the public dataset. Copy the
   value of the `IP_SALT` GitHub secret, so command-file IP hashes match
   earlier versions. mirage-crawl's `.env.export` gets the same five values,
   because its exporter hashes IPs with the same salt so the two datasets
   join.
   Also give the exporter its own read-only database login, and put
   `DB_USER=mirage_export` and `DB_PASSWORD=<it>` in mirage-core's
   `.env.export`. `dataset-export` loads only `.env.export`, so it never sees
   the main database password:

   ```sql
   CREATE ROLE mirage_export LOGIN PASSWORD '<generated>';
   ALTER ROLE mirage_export SET default_transaction_read_only = on;
   GRANT CONNECT ON DATABASE mirage TO mirage_export;
   GRANT USAGE ON SCHEMA public TO mirage_export;
   GRANT SELECT ON sessions, commands, auth_attempts, bait_interactions TO mirage_export;
   ```
3. Install and start the timer:

   ```bash
   sudo cp deploy/dataset-export/mirage-dataset-export.{service,timer} /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now mirage-dataset-export.timer
   # First run backfills all history. Measured on the Nuremberg sensor, Oct 2026:
   # ~4.5 min through 2026-W42 (69 MB); a 5.6M-command telnet week adds ~7 min.
   sudo systemctl start mirage-dataset-export.service
   journalctl -u mirage-dataset-export.service -f
   ```

A week is published one day after it ends, once the ML bridge has classified
every finished SSH session in it (or after 7 days regardless; the manifest
records how many were still unclassified). Re-running is always safe: a week
already in the manifest is skipped, and a run that died mid-upload simply
redoes that week next time.

Reading it, e.g. with DuckDB, after `INSTALL httpfs; LOAD httpfs;`:

```sql
-- the file list comes from manifest.json, since HTTP can't glob
SELECT country, count(*) FROM read_parquet([
  'https://<public bucket URL>/sessions/protocol=ssh/week=2026-W42.parquet',
  'https://<public bucket URL>/sessions/protocol=ssh/week=2026-W43.parquet'
]) GROUP BY 1 ORDER BY 2 DESC;
```
