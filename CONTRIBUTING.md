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
