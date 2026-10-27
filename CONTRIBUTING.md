# Contributing to MIRAGE

Thanks for your interest in MIRAGE. This is a defensive security research
project — an SSH honeypot and threat-intelligence pipeline. Contributions of
code, sensors, analysis, and documentation are welcome.

## Ground rules

- **Defensive use only.** MIRAGE is for observing unsolicited attacker traffic on
  infrastructure you own or are explicitly authorised to operate. Contributions
  must not add offensive capability (scanning, retaliation, exploitation of third
  parties) or detection-evasion intended for malicious use. See the ethical notice
  in `README.md` and `SECURITY.md`.
- **Never commit secrets.** No host keys, API keys, `.env` files, credentials, or
  real captured PII. The SSH host key is generated locally and is gitignored — see
  the incident write-up in `SECURITY.md` for why this matters.
- **Keep the sensor safe to run.** Changes to the SSH server or fake shell must not
  introduce real filesystem access, real network egress, or real command execution.

## Development

- **Go core** (`cmd/`, `internal/`): `go build ./...`, `go vet ./...`, `go test ./...`.
  CI mirrors these (`.github/workflows/go-tests.yml`).
- **Python ML / bridge** (`ml/`, `bridge/`, `scripts/`): tests under `ml/tests`
  run in CI (`.github/workflows/ml-tests.yml`).
- Match the surrounding style; add tests for new behaviour; keep the two sides of
  any cross-language wire contract (e.g. the deception action names) in sync.

## Checking the simulated shell

Two checks measure how closely the simulated shell (`internal/shell`) matches a real Ubuntu 22.04 host.
Neither runs anything on your machine except the Go shell, which has no `os/exec`, network or real-file access.

**Ground truth (needs Docker).** `internal/shell/testdata/ubuntu2204.json` lists commands with the stdout,
stderr and exit status a fresh `ubuntu:22.04` container produced. `go test ./internal/shell` requires the shell to
reproduce every byte.

```bash
make ubuntu-check        # compare the file with the container; changes nothing
make ubuntu-regen        # rewrite every expectation from the container
```

To add a case, append `{"cmd": "..."}` to `"cases"` and run `make ubuntu-regen`. Never edit an expected value to make a
test pass; the value is what Ubuntu printed, and the shell is what gets fixed. A case with no recorded expectation
fails the Go test. The file records the image id and bash version, and `check` warns if yours differs.

**Replay of real commands.** Export the most common commands from a sessions database, then replay them against the
code before the shell fixes and against your tree:

```bash
DATABASE_URL=postgresql://... python3 scripts/export_replay_commands.py --protocol ssh --out /somewhere/ssh.jsonl
make replay-compare REPLAY_FILE=/somewhere/ssh.jsonl        # BASE_REF defaults to ad6b2dc
```

The corpus is attacker-supplied text; keep it outside version control (`replay/` is ignored). Read the result with care:

- A *tell* is a syntax error, or `X: command not found` for any `X` except `xxxxxx`, the botnet self-test's deliberate
  probe, which a real host answers the same way. `ok` means no tell appeared, not that the output was right; the ground
  truth above checks that for the commands it covers.
- Some missing commands are legitimately missing on Ubuntu (an attacker's own binary, `ssh` in a minimal image), so the
  tell rate is an upper bound for those.
- The self-test payload is one command that can dominate the total (12.6% of the Nuremberg corpus, 14.1% of
  Frankfurt's) and flips from a syntax error to correct at once. The second line of output leaves it out; quote that
  one next to the first. On Frankfurt's commands the other 86% went from 96.9% to 98.0%.
- Commands of 4000 bytes or more are left out. That is the 10,972- and 11,956-byte payload variants, 31% of
  Nuremberg's command sessions, which the shell still cannot run.

## Submitting changes

1. Fork and branch off `main`.
2. Make your change with tests and a clear commit message.
3. Open a pull request describing what changed and why.

## Licensing of contributions

By contributing, you agree that your contributions are licensed under the same
terms as the project: **Apache License 2.0** for source code (`LICENSE`), and
**CC BY 4.0** for dataset/data contributions (`DATASET_LICENSE.md`).

## Developer Certificate of Origin (DCO)

All contributions must be signed off under the
[Developer Certificate of Origin](https://developercertificate.org/). This is a
lightweight statement that you wrote the contribution, or otherwise have the right
to submit it under the project's license.

Add a `Signed-off-by` line to every commit:

```
Signed-off-by: Your Name <your.email@example.com>
```

Git can do this automatically with the `-s` flag:

```bash
git commit -s -m "your message"
```

Pull requests whose commits are not signed off will be asked to amend before merge.
