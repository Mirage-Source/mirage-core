package store

import (
	"bytes"
	"strings"
)

// Postgres text and jsonb reject NUL and invalid UTF-8, and attacker-driven
// strings (echo-loader output, credentials, cwd) carry both. One bad value
// fails the INSERT and loses the whole session, so every value bound by
// SaveSession goes through pgArgs. Byte-exact input is kept in raw_input_b64.

const nulEscape = `\u0000`

// pgText replaces NUL and each run of invalid UTF-8 with U+FFFD, matching
// what encoding/json already does for invalid UTF-8.
func pgText(s string) string {
	return strings.ToValidUTF8(strings.ReplaceAll(s, "\x00", "�"), "�")
}

// pgJSON rewrites the \u0000 escape that jsonb rejects. It walks escapes so a
// literal backslash before "u0000" (marshalled as `\\u0000`) is left alone.
func pgJSON(b []byte) []byte {
	if !bytes.Contains(b, []byte(nulEscape)) {
		return b
	}
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] != '\\' || i+1 == len(b) {
			out = append(out, b[i])
			continue
		}
		if bytes.HasPrefix(b[i:], []byte(nulEscape)) {
			out = append(out, `�`...)
			i += len(nulEscape) - 1
			continue
		}
		out = append(out, b[i], b[i+1])
		i++
	}
	return out
}

// pgArgs returns a copy of args with text and JSON values made storable.
// []byte args are always marshalled JSON here.
func pgArgs(args []any) []any {
	out := make([]any, len(args))
	for i, a := range args {
		switch v := a.(type) {
		case string:
			out[i] = pgText(v)
		case *string:
			if v != nil {
				s := pgText(*v)
				out[i] = &s
			} else {
				out[i] = v
			}
		case []byte:
			out[i] = pgJSON(v)
		default:
			out[i] = a
		}
	}
	return out
}
