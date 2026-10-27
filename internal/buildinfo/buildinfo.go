// Package buildinfo carries the identity of the running binary.
//
// Commit is set at link time by the Dockerfiles:
//
//	-ldflags "-X github.com/mirage-source/mirage-core/internal/buildinfo.Commit=$(sh scripts/build_sha.sh)"
//
// An unstamped binary reports "unknown", which the daily health check treats as
// a finding rather than as a revision.
package buildinfo

// Commit is the short sha of the tree the binary was built from (scripts/build_sha.sh).
// A "-dirty" suffix means the build included uncommitted or untracked files.
var Commit = "unknown"
