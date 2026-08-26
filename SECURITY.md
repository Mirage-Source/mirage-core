# Security

## Reporting

This is a research/portfolio honeypot project. If you find a vulnerability that
affects the safety of the deployed sensor (e.g. a real container escape, not a
honeypot-detection issue), open an issue or contact the maintainer directly
rather than filing a public exploit walkthrough.

## Rules of engagement

MIRAGE includes an optional adaptive-deception layer (`internal/deception`,
`ml/mirage/deception/`) that can, when `MIRAGE_DECEPTION_APPLY_ACTIONS=true`,
alter shell responses to draw out further attacker behavior -- including
`FAKE_SUCCESS`, which rewrites a failing command's exit code to a silent
success. On a live internet-facing sensor this raises a real question: is the
system ever inducing an attacker to stage something that then gets reflected
back as if it happened? The ceiling below is a hard constraint, not a tuning
knob, regardless of which deception action is active:

- **No outbound connection from the simulated shell ever completes.** This
  holds structurally, not just by policy: `internal/shell` imports no
  networking package (no `net`, `net/http`) and no process-execution package
  (no `os/exec`). Every command is dispatched from a fixed whitelist (`echo`,
  `whoami`, `pwd`, `hostname`, `id`, `uname`, `export`, `test`, `cat`, `ls`,
  `cd`, `grep`, `head`, `tail`, `wc`, `exit`); anything else -- `wget`,
  `curl`, `nc`, `ssh`, `scp`, `telnet`, `ping`, a Python one-liner opening a
  socket -- falls through to the same `"command not found"` response every
  other unrecognized command gets. There is no code path in the shell that
  can dial out, regardless of what an attacker types.
- **No real payload execution.** Nothing in `internal/shell` shells out to
  the host OS; command output is entirely simulated/templated
  (`internal/shell/fs.go`), never the result of actually running what was
  typed.
- **`FAKE_SUCCESS` only rewrites an already-computed result.** `Apply`
  (`internal/deception/apply.go`) runs *after* the shell has already produced
  a `(response, exit code)` pair from the two guarantees above; it can turn a
  127/"command not found" into a `0`/silent response, but it cannot make the
  underlying (nonexistent) operation real, and it never fabricates response
  content -- masked commands return empty output, not invented data.
- **No fabricated data that could be reused against a third party.** Bait
  content and command output are static/templated, not derived from or
  proxied through any live external source, so nothing MIRAGE emits can be
  replayed elsewhere as if it were real infrastructure belonging to someone
  else.

This is enforced as a regression, not just documented: `internal/shell`'s
`TestShellPackageHasNoEgressCapableImports` fails the build if the package
ever imports a networking/exec package, `TestNetworkFlavoredCommandsNeverAttemptRealEgress`
runs a battery of network/exec-flavored commands through the interpreter and
asserts each resolves immediately to the simulated `"command not found"`
path, and `internal/deception`'s `TestFakeSuccessNeverMasksARealAttempt`
locks in that `FAKE_SUCCESS` applied on top still completes immediately with
empty output.

## Disclosed incidents

### 2026-07-11 — SSH host private key committed to git history

The Ed25519 private host key (`config/hostkey`) was briefly committed in
`feaa5458` alongside its public counterpart, then removed from tracking two
commits later in `75d0b419`. Removing the file from `HEAD` does not remove it
from history — the key remained fully recoverable from the repository's git
history on a public GitHub remote.

**Impact:** anyone who cloned the repo could extract the private key and
impersonate the honeypot's SSH host identity.

**Remediation:**
- The live host key had already been rotated independently of this fix; the
  leaked key was not the one in production use at time of discovery.
- History was rewritten with `git-filter-repo` to strip `config/hostkey` and
  `config/hostkey.pub` from every commit on every affected branch (`main`,
  `core`, `ml`, `ml-intelligence-layer`), and force-pushed.
- `config/hostkey*` is gitignored; the key is generated locally via
  `scripts/generate_hostkey.sh` and never committed.

If you have an existing clone from before this fix, discard it and re-clone —
the rewritten history is not fast-forwardable from the old one.
