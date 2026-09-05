# Decisions

Append-only log of nontrivial choices — one entry per decision, in the
order they were made.

## 2026-08-24 — Stratified sampling for apt-label hand-labeling

**Chose:** Stratify the few-hundred-session hand-labeling sample by the
weak-label heuristic's own predicted `attacker_class`, oversampling rare
classes (`apt`/`manual_recon`) relative to their true frequency in traffic.

**Why:** Real SSH honeypot traffic is bot-dominated; a pure random sample
of a few hundred sessions would likely contain few or zero `apt`/
`manual_recon` examples, giving no statistical power to evaluate exactly
the classes a review comment flagged as under-validated. Trade-off: no
single accuracy number from this sample can be read as "expected
real-world accuracy" — per-class agreement (confusion matrix, per-class
precision/recall) has to be reported instead of a figure reweighted to the
true class mix.

**Alternative considered:** Pure random sampling (reflects true traffic
distribution but starves the rare classes of examples); stratifying by
`classifier_confidence` bins instead of predicted class (tests confidence
calibration rather than class-label correctness — a different, also
useful, question, but not what the review comment asked for).

**My answer before seeing yours:** Stratified by heuristic-predicted
class — matched what you picked.

## 2026-08-24 — Gold-label storage: repo file, not a DB column

**Chose:** Store hand-labeled ground truth in a versioned JSONL file in
the repo (`data/labels/gold_labels.jsonl`), keyed by `session_id`, rather
than a new column on the live `sessions` Postgres table.

**Why:** Mirage isn't currently deployed, and the live DB resets on next
start — nothing durable can depend on living only in that table. A repo
file survives every future deploy/redeploy cycle and every `dataset/vN`
export regeneration, and is diffable/reviewable like any other change.

**Alternative considered:** A `human_attacker_class` column on `sessions`
(keeps the label physically next to the session, but not portable and
lost on the next DB reset); a hybrid where the file is authoritative and a
script backfills the DB column (adds complexity with no live DB to
backfill into right now — deferred).

**My answer before seeing yours:** n/a — asked as a multiple-choice
question rather than fully open. You picked file-based storage, citing
the DB's ephemerality — the same conclusion I'd have reached given that
context, but the context (Mirage not currently running) is what settled
it, not a default preference of mine.

## 2026-08-24 — Agreement metric: Cohen's kappa as the headline number

**Chose:** Report Cohen's kappa as the headline agreement number between
human labels and the heuristic's predictions, with a full confusion
matrix and per-class precision/recall/F1 as supporting detail. Raw
accuracy is still shown but explicitly labeled as inflated by class
imbalance rather than hidden.

**Why:** This is exactly the failure mode the review comment is about — a
heuristic "measured against itself" (or against a dominant class) can
look accurate without having learned anything about the rare classes
under question. Kappa corrects for chance agreement; the confusion matrix
says *which* class the heuristic actually confuses, which kappa alone
can't show.

**Alternative considered:** Raw accuracy alone (simplest, but the exact
thing that would let a chance-agreement result masquerade as a real
validation — rejected for that reason); macro-F1 as the sole headline
(informative per-class, but no standard chance-correction and less
standard than kappa for this specific "two raters agree on a label"
framing).

**My answer before seeing yours:** n/a — explicitly deferred to me.

## 2026-08-24 — Blind labeling, enforced structurally

**Chose:** The sampler writes the heuristic's own prediction to a
separate file (`data/labels/heuristic_predictions.jsonl`) that the
interactive labeling CLI (`label_sessions.py`) never opens, so the human
reviewer can't see — and anchor on — the heuristic's guess while
assigning the human label.

**Why:** If the labeling tool showed the heuristic's predicted class
while the human was choosing a label, the human label would tend to agree
with the heuristic from anchoring alone, and the resulting "agreement"
number would reproduce close to the same circularity the review comment
is flagging — just with an extra human-in-the-loop step that doesn't
actually fix the underlying problem.

**Alternative considered:** Showing the heuristic's prediction alongside
the session for the reviewer to confirm/override (faster to review,
closer to how some production labeling pipelines work, but biases the
exact number this whole effort exists to make trustworthy — rejected).

**My answer before seeing yours:** n/a — not asked; this was a design
call I made unilaterally and flagged explicitly rather than posing as a
question, since it directly determines whether the resulting metric means
anything.

## 2026-08-26 — Retire the three live-dependent GitHub Actions workflows

**Chose:** Disable the trigger on `deploy.yml`, `update-stats.yml`, and
`publish-dataset.yml` (drop `push`/`schedule`, keep `workflow_dispatch`),
rather than deleting the files, and left `go-tests.yml`/`ml-tests.yml`
untouched since they don't depend on the live sensor.

**Why:** Mirage is no longer live — the VPS `deploy.yml` pushes to, and
the API `update-stats.yml`/`publish-dataset.yml` poll, no longer exist, so
all three would just fail (or silently no-op) on every scheduled run.
Pausing rather than deleting keeps the workflow re-armable with a
one-line diff (restore the trigger) if the sensor comes back online,
versus reconstructing it from git history.

**Alternative considered:** Delete the files outright (simpler, no dead
config sitting in the repo, but loses the "one line to re-arm" property
and makes reviving deployment/publishing later strictly more work).

**My answer before seeing yours:** n/a — asked as a multiple-choice
question (all three workflows; pause vs. delete). You picked pause, with
the reasoning above matching what I'd have recommended for a project
explicitly described as "no longer live" rather than "shut down for
good."

## 2026-08-26 — Real re-ID identity = source address; campaign tier as an
auxiliary toolkit signal, not identity

**Chose:** For real-data Phase-3 training, use each session's real
`client_ip` as the contrastive-loss identity label (verified ground truth
for every row), and confirmed campaign-tier membership as a *separate*,
weaker "toolkit" label — never asserted as the same identity. Implemented
as a two-granularity loss (`CampaignAwareReIDLoss`): full-strength SupCon
on identity, weighted-down SupCon on toolkit, with the `unknown` toolkit
placeholder excluded from ever anchoring the toolkit term.

**Why:** The preprint's own campaign finding (§VI-A) proves the 50
campaign addresses share identical *tooling*, not that they share one
*operator* — it explicitly declines that attribution claim ("we leave
attribution open"). Treating the whole campaign as one identity would
bake an unverified claim into training data as if it were ground truth —
exactly the failure shape the preprint spent a full section (silent
capture corruption) warning about. Per-IP identity costs nothing extra
(it's already known) and is still a real re-ID test via the existing
held-out gallery/probe split.

**Alternative considered:** Identity = the whole 50-IP campaign as one
class (the stronger, more "interesting" signal, since it would test
cross-IP recognition directly — rejected because it overclaims); identity
= client_ip only, discarding the campaign finding entirely (safest, but
throws away the one place structural ground truth actually exists beyond
IP — rejected as wasteful, and the paper's own §VIII names this as the
open problem worth addressing).

**My answer before seeing yours:** Asked directly, gave three options and
laid out the reasoning above without a recommendation first, per standing
instructions. Confirmed matches my own answer.

## 2026-08-26 — Session metadata (banner/credential/duration) folded into
one token stream, not a separate model branch

**Chose:** Extend `CommandTokenizer`/`Session` so `ssh_client_banner` and
`auth_attempts` (username:credential pairs tried) become vocabulary
tokens inserted right after `<bos>`, and session duration is carried in
the *timing* channel via a new `<dur>` placeholder token — rather than
adding a separate side-channel branch to `SessionEmbedder` fused before
the projection head.

**Why:** 97.2% of real sessions have zero commands and, before this
change, all encoded to the identical `[<bos>, <eos>]` sequence — the
contrastive loss had literally nothing to discriminate on for the
overwhelming majority of the corpus. `SessionEmbedder` already has
sinusoidal positional encoding and masked-mean pooling over every
position (not a CLS token), so a unified token stream loses no real
representational capacity versus a separate branch — verified empirically
by re-running the same 400-step smoke config before/after: recall@1
0.005 -> 0.031, recall@10 0.006 -> 0.099, loss curve went from
non-monotonic (5.62 -> 4.54 -> 4.60) to smoothly decreasing
(3.69 -> 2.80 -> 2.76). Duration specifically goes through the timing
channel rather than a bucketed token, since it's continuous and the
timing channel already exists for exactly this kind of value.

**Alternative considered:** A separate side-channel branch (categorical
banner embedding + hashed credential embedding + scalar duration MLP,
concatenated with the pooled command representation before the
projection head) — architecturally cleaner separation of "sequence" vs.
"session-level" information, but requires changing `SessionEmbedder`'s
signature, `ContrastiveReIDModel.forward`, `ReIDModelOutput`, and every
collator; rejected as unnecessary complexity once duration's own
awkwardness (the only real weak point of the token-stream approach) was
resolved by routing it through the existing timing channel instead of
forcing it into a discretized vocabulary entry.

**My answer before seeing yours:** n/a — you asked me directly whether
quality would degrade with one token stream before deciding; I gave the
technical reasoning above (positional encoding + mean pooling means no
capacity loss, duration is the one soft spot, fixed via the timing
channel) and you approved building it that way.

## 2026-08-26 — Stderr routing implemented as post-hoc output
classification, not a real dual-stream refactor

**Chose:** Model "did this stage's output go to stdout or stderr" by
classifying the *already-computed* single output string via its exit code
(`isErrorChannel`, with one explicit override for `which`), rather than
changing every builtin's signature from `(string, int)` to
`(stdout, stderr string, code int)` and threading two channels through
the whole interpreter.

**Why:** A correctness-review finding flagged that unknown commands
always wrote "command not found" to the same channel as normal output,
and that `2>`/`2>&1` weren't even parsed — a real recon script checking
stderr specifically would catch this. A full dual-stream refactor would
touch every one of the ~20 builtin functions for a benefit the audit
already showed doesn't materialize: across this interpreter's whole
builtin set, exit code is a reliable proxy for "is this error text"
except for `which` (which can exit 1 while still printing real stdout
matches), which the classifier special-cases explicitly rather than
silently getting wrong.

**Alternative considered:** The full two-string-per-builtin refactor
(more "correct" in the abstract, matches how a real shell is actually
built) — rejected as disproportionate: it would touch far more surface
for the same externally-observable behavior, and the audit found no
second case beyond `which` where the classifier's exit-code heuristic
actually diverges from truth.

**My answer before seeing yours:** n/a — this was flagged to you as the
large/architectural piece of a four-part finding, and you gave blanket
approval to work through all four rather than re-litigating this specific
implementation choice; noted here rather than skipped since it's still a
real design fork a reviewer could reasonably ask about.

## 2026-08-26 — Validity toolkit lives in the Go API binary, not a new
Python or JS service

**Chose:** Build the P1 data-validity toolkit (accept-rate band drift,
field-cardinality collapse, campaign-vs-aggregate decomposition, downtime-
vs-silence heartbeat) as a new `internal/validity` Go package, exposed
through the existing `mirage-api` binary and a `//go:embed`-served
dashboard — retiring Prometheus+Grafana rather than adding a third viz
layer. Ported `ml/mirage/reid/campaign.py`'s wordlist-divisibility +
credential-set-identity test to Go by hand (`internal/validity/campaign.go`)
rather than shelling out to the existing tested Python implementation.

**Why:** Every existing Grafana panel already turned out to be a live SQL
query wrapped in a Prometheus gauge (`cmd/api/main.go`) — Prometheus/
Grafana added no data-processing value, just a poll/store/viz layer on
numbers Postgres already had, with full history, more cheaply than
Prometheus's 30-day retention. A second runtime call from Go into Python
for one check would add a cross-language dependency to what's otherwise a
single-binary serving path, for ~60 lines of dependency-free `Counter`
logic that's mechanical to port faithfully (verified against the existing
Python test suite's exact cases, ported 1:1 in
`internal/validity/campaign_test.go`). Keeping this to one binary matches
the explicit "light stack" goal, which matters beyond aesthetics for §05's
still-unbuilt distributed-collector story (Sensor 06): a node other people
run shouldn't need to stand up Prometheus+Grafana+a second language
runtime just to see its own validity checks.

**Alternative considered:** Keep Prometheus+Grafana and add a third
dashboard beside them (less migration work now, but adds a viz layer on
top of infra already shown to be pure pass-through, and doesn't help the
light-stack/fleet-node goal); have the Go API shell out to the existing
Python `campaign.py` CLI and cache its output (reuses the canonical tested
implementation, avoids maintaining two copies of the same logic, but adds
a Python runtime dependency to the serving path and a subprocess-call
failure mode for a check simple enough to duplicate safely).

**My answer before seeing yours:** n/a — you asked me to design this
(scope explicitly deferred: "whatever you prefer"/"I think I want to keep
the whole stack... as light as possible") after two rounds of me asking
you to choose first on the interface and scope questions; noted here
rather than skipped since the concrete architecture (single binary,
hand-ported check vs. cross-language call) is still a real fork worth a
reviewer's scrutiny even though you delegated picking it.

## 2026-08-26 — Downtime-vs-silence needs a real heartbeat, not a session-
gap heuristic

**Chose:** Add a new `sensor_heartbeats(sensor_id, ts)` table, written by
a ticker in the SSH server (`cmd/mirage/main.go`) independent of session
traffic, tagged by a new `SENSOR_ID` env var — rather than trying to infer
downtime from gaps in session arrival alone, and rather than reusing the
existing `sessions.node_id` field for sensor identity.

**Why:** "Sensor was down" and "sensor was up but nobody connected" are
indistinguishable from session data alone by construction — that's the
whole point of the check, so no heuristic on session gaps can actually
answer it; a real out-of-band liveness signal is necessary, not just
preferable. Separately, `sessions.node_id` turned out to be hardcoded to
`"Ubuntu"` (`internal/server/server.go:223`) — the emulated-OS identity
string shown to attackers, not a deployment/sensor identifier — so reusing
it for sensor identity would have been reusing a field for a meaning it
doesn't have, caught while implementing rather than assumed from a
migration comment.

**Alternative considered:** Derive liveness from the `ml-worker`/bridge's
existing 10s poll loop, which already runs continuously — rejected because
it measures the bridge's liveness, not the SSH listener's; the SSH server
could be down while the bridge is still up, producing a false "alive"
reading on exactly the failure this check exists to catch.

**My answer before seeing yours:** n/a — this surfaced during
implementation (checking where `node_id` actually came from before
building on it), not as a question posed to you first; noted here per the
same "real design fork" standard as the entries above.

## 2026-08-26 — Dashboard accepts the API key as a `?api_key=` query param,
in addition to the header

**Chose:** `cmd/api/main.go`'s auth middleware now falls back to
`r.URL.Query().Get("api_key")` when neither `X-API-Key` nor `Authorization:
Bearer` is present, so `GET /dashboard?api_key=...` works from a plain
browser navigation -- rather than requiring every existing REST consumer to
change, or building a login form + cookie session for the dashboard alone.

**Why:** Every other route on `mirage-api` is called by scripts/`curl`,
which can set headers freely; `/dashboard` is the first route a human
loads by typing/clicking a URL, and a browser navigation cannot attach a
custom header. The existing model already treats this key as something
"available to researchers on request" (README's REST API section), not a
secret with a stricter threat model like a user password, so accepting it
in a query string for the one route that needs it is a proportionate
trade-off, not a new weaker posture for the whole API -- header/bearer are
still tried first and this is only a fallback.

**Alternative considered:** A real login flow (password form → signed
cookie) -- the correct answer for a multi-user product, but disproportionate
build for a single shared API key that's already handed out manually
per-researcher; would also be the first stateful/session-carrying thing in
an otherwise fully stateless API.

**Known weakness, stated plainly rather than glossed over:** a URL
containing the key can leak via browser history, a shared clipboard, or an
outbound `Referer` header if the dashboard ever links offsite (it
currently doesn't). Acceptable for now given the key's existing
distribution model; would need revisiting before ever making the dashboard
route reachable from the open internet rather than an operator's own
tunnel/VPN.

**My answer before seeing yours:** n/a -- this is a mechanical consequence
of the browser-can't-set-headers constraint discovered while wiring
`/dashboard` into the existing all-routes-need-a-header middleware, not a
question with a real design fork posed to you; logged anyway since it's a
security-relevant trade-off a reviewer should be able to see was made
deliberately, not accidentally.

## 2026-08-26 — LLM shell completion: multi-vendor from the start, over an
Anthropic-only v1

**Chose:** Ship the P2 completion fallback with a two-implementation provider
abstraction — `AnthropicProvider` (forced tool-use) and
`OpenAICompatibleProvider` (OpenAI SDK against a configurable `base_url`) —
selectable per deployment and switchable at runtime from the dashboard.

**Why:** You asked for full multi-vendor rather than the narrower option I
proposed, so operators aren't locked to one API for a feature that costs them
money on their own infrastructure. The lift is contained because one
`OpenAICompatibleProvider` covers OpenAI *and* every self-hosted runtime worth
naming — Ollama, vLLM and LM Studio all speak the OpenAI chat-completions API,
so "self-hosted" is a `base_url`, not a third client. That kept multi-vendor
to two implementations rather than one per runtime, and the engine that
surrounds them (cache, budgets, breaker) is vendor-agnostic and tested
entirely through fakes.

**Alternative considered:** Anthropic-only with selectable model tiers — my
recommendation, on the grounds that `ml/mirage/intel/summarize.py` is the only
proven LLM integration here and it runs in a latency-insensitive background
path, while this one sits on an attacker's interactive prompt where every new
failure mode is felt immediately. Rejected in favour of operator choice.

**My answer before seeing yours:** n/a inverted — I gave my recommendation
first (Anthropic-only, model tiers) and you chose the broader option. Logged
because the divergence is the interesting part: the risk I was pricing was
"more vendor surface on a real-time path", and the mitigation that made your
choice cheap was realising the OpenAI protocol is a de-facto standard for
self-hosting, which collapses three runtimes into one client.

## 2026-08-26 — The completion fallback refuses compound lines outright

**Chose:** `ShouldAttemptCompletion` returns false for any line containing
`;`, `&&`, `||`, `|`, `<`, `>`, `$(`, backticks or `&` — the whole line goes
to the real interpreter instead.

**Why:** A completion replaces the output of the *entire line*, but eligibility
is decided from the *first word*. Without this rule `uptime; wget http://evil`
would be judged on `uptime`, and the `wget` stage would be answered by a model
rather than by the interpreter that knows to refuse it — quietly defeating the
egress ceiling in SECURITY.md through a gap in parsing, not in policy. Refusing
compound lines makes the "first word decides" shortcut sound, instead of making
the gate parse shell grammar it would then have to keep in sync with
`evalLine`.

**Alternative considered:** Per-stage completion — tokenize the line, complete
only the eligible stages, let the interpreter run the rest. Strictly more
capable, and the right end state if compound lines turn out to matter, but it
means reimplementing (and re-verifying) the interpreter's own parsing in the
gate, for commands the preprint shows are overwhelmingly issued one at a time.

**My answer before seeing yours:** n/a — this surfaced while writing the gate's
tests, not as a question posed to you. Logged because "why does a chained
command never get completed?" is exactly the kind of thing a reviewer would
ask, and the answer is a deliberate safety property rather than an oversight.

## 2026-08-26 — Completion state stays in memory, not Postgres

**Chose:** The per-session response cache, budget counters, circuit-breaker
state and the active-provider pointer all live in `CompletionEngine`'s
in-memory dicts, guarded by one lock and TTL-evicted — mirroring
`LiveDeceptionEngine`. Nothing is persisted; a restart resets the active
provider to `MIRAGE_LLM_SHELL_ACTIVE_PROVIDER`.

**Why:** `mirage-deception` today has *zero* Postgres dependency (its compose
block says so explicitly), and it has no `depends_on` precisely so it can
start, fail, or be absent without affecting the honeypot. Adding a database
connection so one mutable string survives a restart would trade that
independence for very little: the cache is session-scoped and worthless after
a restart anyway (sessions are gone), and budgets resetting on restart is
acceptable for a process that restarts rarely.

**Alternative considered:** A small Postgres-backed runtime-config table, which
would make the dashboard's provider choice durable and would generalise to a
future multi-instance deployment. Worth revisiting if this service is ever run
with more than one replica — at that point in-memory budgets stop being global
and the breaker stops being shared, which is the real trigger for persisting.

**My answer before seeing yours:** n/a — implementation-level call made while
building; noted since "why isn't the provider choice saved?" has a real answer
worth being able to give.

## 2026-08-30 — mirage-web lives in its own repo, not a mirage-core subdirectory

**Chose:** The collaborator-built dashboard (`mirage-web`, Next.js) is its own
git repo, checked out as a sibling directory to `mirage-core`
(`../mirage-web`), not committed inside this repo.

**Why:** mirage-core's schema (`sessions.node_id`, `GET /api/sensors`) is
already built for multiple honeypot sensors reporting into one central
API/DB — sensor count scales by adding rows with different `node_id`, not by
redeploying mirage-core per sensor. mirage-web talks to that one central API
regardless of sensor count, so its deploy lifecycle (singleton, redeployed
occasionally) doesn't match mirage-core's (cloned/pulled once per sensor
node). Bundling it as a subdirectory would drag a full Next.js app onto every
future sensor host. The collaborator had also already built it as an
independent unit (own `.gitignore`, README, lockfile), so the repo boundary
was already drawn in practice.

**Alternative considered:** Subdirectory in mirage-core with
`docker-compose.yml` building `./mirage-web` directly — rejected once the
multi-sensor plan came up, since compose can reference a sibling checkout
just as easily and the deploy topology should drive the repo boundary, not
compose-file convenience.

**My answer before seeing yours:** n/a — Vinayak asked for my reasoning
directly rather than answering first; the deciding factor (central API,
scaling sensors by `node_id` not by redeploying mirage-core) only became
clear once he named the multi-sensor plan.

## 2026-08-30 — netcup VPS 1000 G12 (Nuremberg, DE) replaces Frankfurt sensor

**Chose:** netcup VPS 1000 G12, Nuremberg DE, flat monthly billing, zero-month
commitment. ~4GB RAM / 2 vCPU, comfortably clears the compose stack's summed
memory limits (~3.6GB across postgres/mirage-core/ml-worker/mirage-deception/
mirage-api).

**Why:** Live-priced against Hetzner (CPX22, 4GB EU, no commitment: €19.99/mo),
DigitalOcean (Basic Droplet 4GB, no commitment: $24/mo), and Hostinger
(cheapest 4GB tier only available via a 24-month upfront prepay). netcup was
roughly half the cost of Hetzner/DO for an equivalent no-commitment box — a
surprise, since Hetzner has a stronger price-performance reputation, but its
cheap CX line was sold out everywhere and the in-stock CPX line priced higher
than expected. Nuremberg (not "no preference Europe") was pinned explicitly
to keep country-level geo attribution consistent with the retired Frankfurt
sensor, rather than leaving it to a checkout default that could land in
Austria or the Netherlands.

**Alternative considered:** Contabo's advertised low price requires a
24-month prepay, not comparable to the others' pay-monthly terms. Hostinger's
cheap tier has the same issue. "No preference Europe" (saves ~€1.53/mo) was
rejected because it trades a known, citable sensor location for an unknown
one, for a saving too small to matter (~₹150/mo).

**My answer before seeing yours:** n/a — this was pure market research, not a
design tradeoff with a right/wrong answer to guess at up front.

## 2026-08-30 — Real admin SSH moved to port 2222, honeypot keeps port 22

**Chose:** Host sshd listens on 2222 only; docker-compose's existing
`"22:2222"` mapping for the mirage-core container is untouched, so the fake
honeypot SSH is what the public internet reaches on port 22.

**Why:** The container mapping was already fixed in docker-compose.yml before
this deployment; the only free variable was where real admin access should
live instead. 2222 was picked over a high random port for memorability, and
because a scanner sweeping for the honeypot on 22 has no reason to also probe
2222 specifically for a management port.

**Alternative considered:** A high random port for extra obscurity against
port-sweep discovery. Rejected as unnecessary — combined with key-only auth
and now a default-deny ufw policy, the marginal benefit of hiding the port
number didn't seem worth losing the memorability.

**My answer before seeing yours:** "so remove 2222 from the docker compose of
Mirage maybe, keep 22 to be the honeytrap port and 2222 for when I wanna ssh
in" — this is what got implemented as-is.

## 2026-08-30 — Cloudflare Tunnel for mirage-web, not a direct reverse proxy

**Chose:** Cloudflare Tunnel (cloudflared) fronting mirage-web on vtyagi.dev,
rather than a Caddy/nginx reverse proxy terminating TLS directly on the VPS's
public IP.

**Why:** Hides the origin IP for the operator console specifically (reducing
its attack surface independent of the honeypot, which is deliberately fully
exposed), gives free automatic TLS with no certbot/renewal upkeep, and lets
ports 80/443 stay closed in ufw entirely. Matches the `baremetal` Cloudflare
Tunnel pattern already used elsewhere.

**Alternative considered:** Caddy with automatic Let's Encrypt certs on a
direct A record — simpler, no Cloudflare account dependency, but exposes the
origin IP and requires opening 80/443 to the internet for ACME + serving.

**My answer before seeing yours:** "Used to use tunnel before can go with
that again" — consistent with the alternative I'd have proposed anyway; no
divergence.

## 2026-08-30 — Runner reaches the sensor API over an SSH forward, not a public hostname

**Chose:** `update-stats.yml` and `publish-dataset.yml` are re-armed on their
original schedules and open a short-lived SSH port-forward to
`127.0.0.1:8080` on the sensor (shared composite action
`.github/actions/sensor-api-tunnel`), using a key pinned in `authorized_keys`
to `permitopen="127.0.0.1:8080",command="/bin/false"`. The API stays off the
Cloudflare Tunnel and off the public internet. `API_URL` is retired.

**Why:** The alternative that keeps the API private *and* is simpler to
operate — running the exports on the VPS under systemd timers — requires a
git credential with push access to the public repo to live on the honeypot
host. That host is the one machine deliberately exposed on port 22; a
container escape currently yields honeypot data, and under that design would
yield repo write access. The forward puts no credential on the sensor at all.
Second reason: a failing systemd timer is silent, and the failure mode is a
dataset that quietly stops updating; a failing scheduled workflow emails.

**Alternative considered:** (a) A second tunnel hostname for the API, guarded
only by the shared `X-API-Key` — rejected as new public attack surface for the
operator-side API, which is exactly what the Cloudflare Tunnel decision was
meant to avoid. (b) Inverting to VPS-side systemd timers — rejected on the
blast-radius and observability grounds above.

**My answer before seeing yours:** "leaning towards inverting it and running
exports on the VPS" — asked for a recommendation first, then went with the
forward once the push-credential-on-the-honeypot consequence was spelled out.

---

## 2026-08-30 — Dataset restarts as a new series (`g2-v1`), not `v7`

**Chose:** `publish-dataset.yml` carries `SENSOR_GENERATION=g2` and numbers
within the generation, so the Nuremberg sensor publishes `g2-v1` onward while
Frankfurt's `v1`…`v6` stay frozen. `export_dataset.py` gained
`--sensor-generation`, stamped into `stats_summary.json`.

**Why:** The two corpora come from different hosts, different IPs and a gap in
collection. Continuing the counter would make `v7` look like more of `v6`
while being a near-empty first week from an unrelated vantage point, and
anything downstream that concatenates versions would silently produce a
dataset that no single sensor ever observed.

**Alternative considered:** Continue at `v7` on the same `IP_SALT`
(comparable hashed IPs across the cut, but no marker for the discontinuity),
or continue at `v7` with a rotated salt (breaks the join by accident rather
than by declaration).

**My answer before seeing yours:** picked "new series, note the
discontinuity" from the options offered; no divergence.

---

## 2026-08-30 — deploy.yml stays on workflow_dispatch

**Chose:** Left manual. Only the stale "Mirage is no longer live" header was
removed.

**Why:** The box was just hand-configured, and the deploy script still assumes
`~/mirage-core` and does not apply the hand-written migrations from
`internal/store/migrations/` that `db/init/` is behind on. Auto-deploying on
every merge to main before those two gaps close means a merge can leave the
sensor schema-behind with no one watching.

**Alternative considered:** Restore the `push` trigger, either as-is or
bundled with fixes to the path and a migration catch-up loop. Deferred rather
than rejected — the fixes are worth doing, just not as a side effect of
re-arming the data workflows.

**My answer before seeing yours:** picked "keep workflow_dispatch only" from
the options offered; no divergence.

---

## 2026-08-30 — Two separate keys on the sensor, not one reused deploy key

**Chose:** Generated `mirage_deploy` (shell access, `deploy.yml` only) and
`mirage_api_forward` (pinned to `permitopen="127.0.0.1:8080",command="/bin/false"`,
data workflows only) and installed both in root's `authorized_keys` on
152.53.239.121. `deploy.yml`'s `cd ~/mirage-core` corrected to
`/opt/mirage/mirage-core`, which is where the clone actually is. `API_URL`
deleted from the repo secrets.

**Why:** The two workflows need different amounts of power — one needs a shell
to run `docker compose`, the other needs one TCP forward — and giving both the
same key means a leaked data-workflow secret is a shell on the sensor. The
`command="/bin/false"` restriction is verified, not assumed: with the forward
key, `ssh ... 'echo I_GOT_A_SHELL'` exits 1 with no output, `-L
18080:127.0.0.1:8080` succeeds and serves `/api/stats`, and `-L
15432:127.0.0.1:5432` binds locally but the connection is reset on first byte.

**Alternative considered:** One deploy key for all three workflows, which is
what the retired setup did. Rejected once the keys had to be regenerated
anyway — the split costs one extra secret and no operational complexity.

**My answer before seeing yours:** n/a — mechanical follow-through on the
forward decision above.

---

## 2026-09-05 — Runtime flags: Postgres table + poll, not LISTEN/NOTIFY or an admin port

**Chose:** A `runtime_flags` table (`internal/store/migrations/010_runtime_flags.sql`),
scoped to exactly the two flags mirage-web's `docs/API-GAPS.md §4` marks as
the ones that matter (`deception_enabled`, `deception_apply_actions`).
`deception.Runtime.PolicyEnabled`/`ApplyActions` became `atomic.Bool` instead
of plain `bool`, and `NewRuntime` now always returns non-nil (previously nil
meant "everything off" — that invariant is gone, since a live toggle needs a
real `*Runtime` to flip even when it started fully disabled).
`internal/server.watchRuntimeFlags` polls the table every
`MIRAGE_RUNTIME_FLAGS_POLL_SECONDS` (default 3s) on `mirage-core`'s existing
DB connection and swaps the atomics; `mirage-api` gets a plain
`GET/PUT /api/config` that reads/writes the same table.

**Why:** The dashboard toggle was explicitly asked for, gated on the
mutating endpoint actually being protected since "it would be out on the
web" — `PUT /api/config` inherits the same `X-API-Key` middleware every
other mirage-api route already has, and on the browser side mirage-web's
`src/proxy.ts` gates all of `/api/console/*` behind the operator session
cookie, so nothing new had to be built for that part. That left only the
propagation question. mirage-core's own documented contract for this feature
(mirage-web's Control tab copy: "Changes take effect on the next connection.
No restart, no redeploy.") never promised sub-second push, so a poll
comfortably clears the bar with far less code than LISTEN/NOTIFY: no
persistent listener connection to reconnect on drop, no trigger to maintain,
and the failure mode on a DB hiccup is "stays at the last-known value,"
identical to how every other `deception.Client` call already fails safe.

**Alternative considered:** Postgres `LISTEN/NOTIFY` for true instant push.
Rejected for now — strictly better propagation latency, but real added
complexity (a dedicated long-lived listener connection, reconnect/backoff
handling) for a feature whose own spec only asks for "no restart." Also
considered: an admin HTTP endpoint directly on `mirage-core`, mirroring the
existing LLM-provider-active pattern in `mirage-deception`. Rejected because
`mirage-core` is the one process in this stack directly reachable from the
whole internet by design (it's the honeypot) — adding any inbound admin
surface to it, even API-key-gated, grows that attack surface for a feature
that doesn't need it: `mirage-core` already holds an outbound DB connection
it can poll on, so no new port was necessary at all.

**My answer before seeing yours:** n/a — the persistence model (DB-backed +
push, gated on protecting the endpoint) was asked and answered directly; poll
vs. LISTEN/NOTIFY and the atomic-bool/never-nil `Runtime` change are the
mechanical follow-through on that answer.

---

## 2026-09-05 — Login identity: full root emulation, not just the prompt symbol

**Chose:** `whoami`, `id`, the prompt's `user@host` and `#`/`$` character,
home directory (`~`/`cd` with no args), and new-file ownership on `>`/`>>`
all now derive from `conn.User()` (threaded through as
`sessionGuard.username()` → `shell.NewInterpreter(username)`). Only `root`
gets its own identity (`/root`, `uid=0(root)`, `#`); every other accepted
username in `config/weak_credentials.txt` (`admin`, `mysql`, `postgres`,
`guest`, ...) still collapses onto the existing single `ubuntu` identity.

**Why:** `weak_credentials.txt` accepts `root` logins, but the shell
previously hardcoded `"ubuntu"`/`uid=1000`/`/home/ubuntu` regardless of which
username actually authenticated — so a `root` login got a `$` prompt, and
`whoami` would contradict the prompt's own `user@host` the moment either one
changed. A real box ties the `#`/`$` convention to UID, not login method, so
fixing only the prompt character while leaving `whoami`/`id` saying `ubuntu`
would have introduced a new, sharper contradiction (prompt says root,
`whoami` says otherwise) — worse than the original single-identity gap. The
non-root service-account usernames (`mysql`, `postgres`, ...) deliberately
don't get their own identities: a real box would never hand any of those an
interactive shell at all, so modeling them as `ubuntu` is the realistic
choice, not a shortcut.

**Alternative considered:** flip only the prompt's trailing character based
on login username, leaving `whoami`/`id`/home dir untouched. Rejected for the
self-contradiction reason above — surfaced directly during the discussion
that led here.

**My answer before seeing yours:** n/a — asked directly as a choice between
"just the prompt symbol," "full per-identity emulation for root," or leaving
the gap as-is; "full per-identity emulation for root" was the answer given,
not mine to diverge from.

---

## 2026-09-06 — `ls` learns its flags; long-form entry order stays as-is

**Chose:** `lsBuiltin`/`lsListing` now branch on `-l` (long format) and `-a`
(dotfiles + `.`/`..`), matching real `ls`: bare `ls` and `ls -a` are short
form (names only, alphabetically sorted, no `total` header); `-l`/`-la`/`-al`
are the long format. The long-format entry order is left exactly as it was
(declaration order in `fs.go`, not alphabetical) — only the new short-form
path sorts.

**Why:** An attacker testing the honeypot noticed bare `ls` and `ls -la`
produced identical output — the builtin never looked at its args at all.
Not sorting the long-format path was a deliberate scope limit, not an
oversight: every existing `-la`-shaped test and the deception
ConditionalChildren/bait-reveal logic (`ENRICH`/`SURFACE_BAIT`) depend on
today's declaration order, and re-sorting that path risked disturbing
behavior nobody asked to change, for a mismatch (unsorted `ls -la`) far less
likely to be noticed than the flag bug itself was.

**Alternative considered:** Sort both forms for full realism in one pass.
Rejected for now as unnecessary scope growth on top of the actual reported
bug — worth revisiting only if it's independently flagged.

**My answer before seeing yours:** n/a — reported directly as a bug, not
posed as a design choice; the sort-only-short-form split is the one
judgment call made while fixing it.
