package shell

// knownBuiltins mirrors execBuiltin's switch cases (shell.go). It exists so
// callers *outside* this package can ask "would the interpreter handle this
// command deterministically?" without running the interpreter and without
// this package needing to know why they're asking.
//
// The LLM-completion fallback (internal/deception) is the caller that needs
// it: it must fire only for commands the builtin table genuinely doesn't
// cover, so that a command with real, curated, self-consistent output never
// gets that output replaced by a model's invention. known_builtins_test.go
// cross-checks this map against an independent transcription of the switch,
// so the two cannot drift apart silently.
var knownBuiltins = map[string]struct{}{
	"":         {},
	"echo":     {},
	"whoami":   {},
	"pwd":      {},
	"hostname": {},
	"id":       {},
	"uname":    {},
	"export":   {},
	"test":     {},
	"[":        {},
	"cat":      {},
	"ls":       {},
	"cd":       {},
	"grep":     {},
	"head":     {},
	"tail":     {},
	"wc":       {},
	"which":    {},
	"find":     {},
	"ps":       {},
	"netstat":  {},
	"crontab":  {},
	"exit":     {},
}

// IsKnownBuiltin reports whether execBuiltin has a case for name -- i.e.
// whether this shell produces deterministic, curated output for it.
func IsKnownBuiltin(name string) bool {
	_, ok := knownBuiltins[name]
	return ok
}
