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
