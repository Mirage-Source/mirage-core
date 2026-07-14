package deception

import (
	"math/rand"
	"time"

	"github.com/mirage-source/mirage-core/internal/shell"
)

// Apply realizes a decided action against a command's (response, exitCode)
// pair, returning the (possibly unchanged) response/code and an additional
// delay the caller should sleep before writing the response.
//
// Only two actions are actively realized today, both safe, generic
// transformations that need no new shell command surface:
//
//   - STALL adds latency before the response is sent -- "the system is
//     slow/busy", which is realistic friction on any command.
//   - FAKE_SUCCESS turns a failing exit code into a silent success -- useful
//     for a shell whose builtin command coverage is still thin, so an
//     unrecognised command doesn't immediately read as "command not found"
//     on a from-scratch honeypot.
//
// MINIMAL, ENRICH, and SURFACE_BAIT currently pass the response through
// unchanged. ENRICH and SURFACE_BAIT are still decided and logged (see
// session.Command.DeceptionAction) -- realizing them as richer output would
// mean dynamically embellishing `ls`/`cat` results or conditionally
// revealing planted secrets, which needs the static filesystem in
// internal/shell/fs.go to support content that can be added at request time.
// That is a deliberate follow-up, not an oversight: changing what `cat` and
// `ls` return needs its own careful review on a filesystem that is otherwise
// fully static and already relied on for BaitHit bookkeeping.
//
// Apply never overrides shell.ExitRequested (the "attacker typed exit"
// sentinel, 257) -- FAKE_SUCCESS rewriting that to 0 would silently prevent
// the session from ever closing on `exit`.
func Apply(action, response string, code int) (string, int, time.Duration) {
	switch action {
	case ActionStall:
		delay := time.Duration(200+rand.Intn(700)) * time.Millisecond
		return response, code, delay

	case ActionFakeSuccess:
		if code != 0 && code != shell.ExitRequested {
			return "", 0, 0
		}
		return response, code, 0

	default: // ActionMinimal, ActionEnrich, ActionSurfaceBait, "" (fallback), or anything unrecognized.
		return response, code, 0
	}
}
