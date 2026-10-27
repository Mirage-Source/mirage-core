# Shortcuts for the shell-fidelity checks. Everything also runs without make; see the scripts named here.
.PHONY: test ubuntu-check ubuntu-regen replay replay-compare

test:
	go test ./...

# Compare internal/shell/testdata/ubuntu2204.json with a real ubuntu:22.04 container (needs Docker).
ubuntu-check:
	python3 scripts/ubuntu_diff.py check

# Rewrite every expectation from the container. Never edit an expected value by hand.
ubuntu-regen:
	python3 scripts/ubuntu_diff.py regen

# Replay real commands through the simulated shell and print how often it gives itself away.
#   DATABASE_URL=postgresql://... python3 scripts/export_replay_commands.py > /path/ssh.jsonl
#   make replay REPLAY_FILE=/path/ssh.jsonl
REPLAY_FILE ?= replay/ssh.jsonl
replay:
	MIRAGE_REPLAY_FILE=$(REPLAY_FILE) go test -v -count=1 -run '^TestReplayCorpus$$' ./internal/shell/ | grep '^REPLAY'

# The same corpus against the code before the shell fixes and against this tree.
BASE_REF ?= ad6b2dc
replay-compare:
	sh scripts/replay_compare.sh $(BASE_REF) $(REPLAY_FILE)
	sh scripts/replay_compare.sh WORKTREE $(REPLAY_FILE)
