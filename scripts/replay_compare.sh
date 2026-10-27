#!/bin/sh
# Run the shell replay (internal/shell/replay_test.go) against one version of the code.
#
#   scripts/replay_compare.sh <git-ref | WORKTREE> <corpus.jsonl>
#
# A git ref is exported with `git archive` into a temp directory, so your working tree is never touched;
# the current replay_test.go is copied in, so every version is judged by the same definition of a tell.
# WORKTREE runs the code as it is on disk. See `make replay-compare`.
set -eu
ref=${1:?usage: replay_compare.sh <git-ref|WORKTREE> <corpus.jsonl>}
corpus=$(realpath "${2:?usage: replay_compare.sh <git-ref|WORKTREE> <corpus.jsonl>}")
here=$(cd "$(dirname "$0")/.." && pwd)
if [ "$ref" = WORKTREE ]; then
    dir=$here
else
    dir=$(mktemp -d)
    trap 'rm -rf "$dir"' EXIT
    git -C "$here" archive "$ref" | tar -x -C "$dir"
    cp "$here/internal/shell/replay_test.go" "$dir/internal/shell/replay_test.go"
fi
cd "$dir"
# -v: go test hides the stdout of a passing test otherwise
out=$(MIRAGE_REPLAY_FILE="$corpus" go test -v -count=1 -run '^TestReplayCorpus$' ./internal/shell/ 2>&1) || { echo "$out" | tail -20; exit 1; }
lines=$(printf '%s\n' "$out" | grep '^REPLAY') || { echo "$ref: the replay printed no result line" >&2; printf '%s\n' "$out" | tail -10 >&2; exit 1; }
# the first line is every command; the second leaves out the botnet self-test payload, which is one command
# that can dominate the total (see the note in replay_test.go)
printf '%s\n' "$lines" | while IFS= read -r l; do printf '%-9s %s\n' "$ref" "${l#REPLAY }"; done
