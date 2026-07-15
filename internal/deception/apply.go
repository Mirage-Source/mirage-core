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
// MINIMAL passes the response through unchanged, same as always. ENRICH and
// SURFACE_BAIT are realized elsewhere -- internal/server's applyDeception
// threads the decided action into internal/shell's Interpreter.RunWithDeception
// *before* the command executes, so ls/cat can render richer or gated
// content directly (see fs.go's EnrichedContent/ConditionalChildren and
// BaitInfo.Hidden). By the time a response reaches this function those two
// actions have already done everything they're going to do, so this file's
// job is only the two actions that are pure post-processing transforms.
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
