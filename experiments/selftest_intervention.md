# Self-test intervention: pre-registration

Written 2026-10-28, before the patched build (`fix/shell-fidelity`) is deployed to the Nuremberg SSH sensor.
This file and `selftest_intervention_analysis.py` are committed first; the commit time is the registration time.
Anything done differently from what is written here is reported as a deviation, with the reason.

## 1. What was found while writing this (read first)

The plan assumed the fingerprinting probe was still arriving. It is not.

- The probe is a 17-line command that reports `UNAME`, `ARCH`, `UPTIME`, `CPUS`, `CPU_MODEL`, `GPU`, `LAST`, then runs a `SHELL_BEHAVIOR` self-test. It has three variants (SHA-256 of the raw bytes in the analysis script): p1 (3,273 B), p2 (11,956 B), p3 (10,972 B, 7 sightings, one address).
- In the snapshot of 2026-10-27, **the last probe session ended 2026-10-24 16:17 UTC.** It was sent by 18 addresses, in 4,949 sessions.
- From **2026-10-25 02:13 UTC**, 13 of those 18 addresses run something else in every session: an SFTP upload of a 3.37 MB file to `/root/.16`, then `chmod +x` and execute it (about 70 sessions a day). None of those sessions contains the probe, and no address sent both on the same day.
- Within the probe sessions, **nothing but the probe was ever run**: 0 of 4,949 sessions, 0 of 18 addresses. p1 and p2 are two steps of one sequence (3,943 sessions run p1 and then p2), so the unit under test is the whole probe sequence, not p1 alone.

So the intervention question (does passing the probe lead to a second stage?) can only be asked if the probe comes back. That is built into the design (section 5).

## 2. Questions

- **H1 (proceed):** with the whole probe sequence answered like a real host, baseline addresses run a command that is not a probe variant in the same session.
- **H1b (react):** the bots change how often they re-run the probe (a failed probe was re-run 2 times and then 8 times per session; a passing one should be run once).
- **H0:** answering the probe changes neither.
- **Descriptive (no hypothesis):** how the live SFTP-and-execute campaign behaves before and after the deploy (section 4).

## 3. Treatment, population, unit

- **Treatment:** the sensor build whose `sessions.build_sha` is the registered new build, versus the regressed build `ad6b2dc` that ran since 2026-10-10. The new build answers the probe correctly; it also changes about 70 other shell behaviors (section 8). The estimate is of the build, not of the probe alone.
- **Population:** the 18 addresses that sent the probe before 2026-10-27 (list fingerprint: SHA-256 `0a7c2808…9fabce` of the sorted, newline-joined list; the list itself is not published). Addresses outside it are reported separately and excluded from the test.
- **Unit:** the source address. Sessions are never treated as independent.

## 4. Outcomes

**Primary.** A *qualifying session* is a probe session that also runs a command whose SHA-256 is not one of the three probe variants. `K` is the number of baseline addresses with at least one qualifying session in the window. Baseline: 0 qualifying sessions of 4,949, `K = 0`.

**Secondary.**
- S1: runs of one variant per session, baseline versus window (medians, address-clustered).
- S2: session duration, same comparison.

**Treatment-delivery check (a condition, not an outcome).** The share of window probe sessions in which every probe command was answered with the `UNAME:` and `FILTER:` lines. Required: at least 90%. Below that, the result is "treatment not delivered", not a null.

**Descriptive, not tested (analysis B).** For the addresses running the SFTP campaign: sessions per address per day, commands per session, and the share of addresses seen in the 7 days before the deploy that are seen again in days 8-14 after. The baseline for this is only the days between 2026-10-25 and the deploy, so it cannot support a hypothesis test.

## 5. Design

- **One deploy, before and after; no switchback.** Alternating builds would halve the exposure of a population that is currently not sending the probe at all, and the baseline is a hard zero that a stable population cannot drift away from on its own. The risk this accepts: a new bot version could start proceeding at the same time. The analysis reports the client banner and `hassh` of any qualifying session against the baseline to look for that.
- **Activation.** The test runs only if, in the window, there are at least 300 probe sessions from at least 8 baseline addresses. Otherwise the result is **NOT TESTABLE: no exposure**, which is not a null result.
- **Window.** 14 days from the first session carrying the new `build_sha`. If activation is not met, it is extended in 7-day steps to at most 28 days, then closed as not testable. The analysis runs once, after the window closes. No interim looks, except safety (below).
- **Reversal check, only if H1 is supported.** Roll back to the previous image for 7 days and report whether qualifying sessions disappear.
- **Safety stop.** If the health check fails, or daily session volume stays below half the 14-day median, roll back. That is logged as a deviation.

## 6. Decision rule and what the design can detect

Reject H0 if `K >= 3`.

The baseline gives a 95% upper bound of 0.00061 qualifying sessions per probe session (rule of three on 0 of 4,949). Over 14 days that is at most 0.042 per address (about 70 sessions each). With 17 exposed addresses, the chance of `K >= 3` under that pessimistic null is at most **0.032**. Power, if a true share of addresses proceeds:

| True share of addresses that proceed | 10% | 15% | 20% | 25% | 30% | 40% |
|---|---|---|---|---|---|---|
| Power of `K >= 3` out of 17 | 0.24 | 0.48 | 0.69 | 0.84 | 0.92 | 0.99 |

**This design detects a large effect: about a quarter of the addresses.** A "do not reject" result means fewer than roughly 1 in 4 addresses proceed. It does not exclude a small effect.

## 7. Reported whatever the result

The verdict line of the script, the activation and delivery numbers, S1 and S2, the count of new addresses, and analysis B. A null is reported as a null.

## 8. Threats and confounds, stated in advance

- **The probe stopped on its own.** Whether it returns is outside the experiment. The campaign changed on 2026-10-25, so the bots may have been updated. This is why activation is a condition.
- **Many changes ride along with the treatment.** `sudo -S` now works (the regressed build printed `sudo: command not found` for every chain the live campaign sends), and the shell, `awk`, `printf` and error messages follow real Ubuntu. A change in behavior is attributable to the build, not to the probe.
- **GPU and LAST are blank** in the new build's answer to the probe. A real host would print values. If bots use them, "answered like a real host" is only partly true.
- **A hardware-randomization experiment** is described in `DECISIONS.md` (2026-09-27). The code and data show no arm assignment: in probe sessions the deception action is `ENRICH` on 96.5% of commands. The distinct values per window are reported as a covariate; if an arm is introduced during the window, it is a deviation.
- **Machine identity** is random per SSH connection (`DECISIONS.md` 2026-10-18), so a bot sees a different hostname each time.
- **Small cluster count.** About 17 addresses; the 74-IP / 22-/24 clustering noted in `DECISIONS.md` suggests the effective number may be lower.
- **One sensor.** The result concerns the Nuremberg SSH sensor only.
- **The §3.1 hash in the session log** (`00111095…`) could not be reproduced from the data and is not used; variants are identified by the SHA-256 of their raw bytes.

## 9. Pre-deploy checks (done 2026-10-28)

- `go test ./internal/...` passes; the shell is checked against `ubuntu:22.04` on 700 cases with 0 differences; the replay is 98.0% on the Nuremberg list.
- 40 live commands since 2026-10-25 run through the regressed and the new shell: no difference other than a wall-clock timestamp. The 63 distinct SFTP-campaign chains differ in one visible way, the `sudo` behavior above.
- The deploy workflow did not set `BUILD_SHA`, so every session would have been stamped `unknown`. Fixed in the same commit series.

## 10. Procedure

1. Merge the branch to `main` and run the deploy workflow (it now stamps `BUILD_SHA`). Build from a clean checkout so the stamp has no `-dirty` suffix.
2. Record the exact UTC time of the first session whose `build_sha` is the new one, and the previous image tag, in the repository.
3. Watch the health check daily. Do not look at outcomes before the window closes.
4. After the window, take a snapshot with the existing repeatable-read query, check its checksum, and run the analysis script once.
