package main

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/mirage-source/mirage-core/internal/api"
)

// exportPageSize is what the full-dump path pulls per query. Small enough that
// one page's rows are cheap to hold, large enough that 54k sessions is ~27
// queries rather than hundreds.
const exportPageSize = 2000

// maxExportPages bounds the full dump so a cursor bug cannot loop forever.
const maxExportPages = 5000

// exportWriteTimeout replaces the server-wide WriteTimeout for the full dump,
// which is the one response whose size grows with the corpus.
const exportWriteTimeout = 5 * time.Minute

type pageFetcher func(after string, limit int) (*api.ExportResponse, error)

// streamExport writes the whole session export as one JSON object, fetching it
// a page at a time and encoding each session as it arrives. The response shape
// is identical to the unpaginated version it replaced, but only one page is
// ever held in memory.
//
// An error partway through cannot become a status code -- the body is already
// on the wire -- so it stops and returns, leaving the JSON unterminated. That
// is deliberate: a truncated body fails the client's parse, which is a visible
// error, where a well-formed body with missing sessions would not be.
func streamExport(w io.Writer, generatedAt string, fetch pageFetcher) error {
	if _, err := fmt.Fprintf(w, `{"generated_at":%q,"sessions":[`, generatedAt); err != nil {
		return err
	}

	enc := json.NewEncoder(w)
	after := ""
	total := 0

	for page := 0; page < maxExportPages; page++ {
		batch, err := fetch(after, exportPageSize)
		if err != nil {
			return err
		}

		for i := range batch.Sessions {
			if total > 0 {
				if _, err := io.WriteString(w, ","); err != nil {
					return err
				}
			}
			if err := enc.Encode(batch.Sessions[i]); err != nil {
				return err
			}
			total++
		}

		if batch.NextCursor == nil {
			break
		}
		after = *batch.NextCursor
	}

	_, err := fmt.Fprintf(w, `],"session_count":%d}`, total)
	return err
}
