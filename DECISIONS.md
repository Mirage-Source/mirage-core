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
