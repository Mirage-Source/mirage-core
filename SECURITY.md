# Security

## Reporting

This is a research/portfolio honeypot project. If you find a vulnerability that
affects the safety of the deployed sensor (e.g. a real container escape, not a
honeypot-detection issue), open an issue or contact the maintainer directly
rather than filing a public exploit walkthrough.

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
