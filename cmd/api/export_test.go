package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/mirage-source/mirage-core/internal/api"
)

// fakePages serves n sessions across as many pages as the requested limit
// implies, mimicking GetExportPage's cursor contract: a cursor is returned
// only when the page came back full.
func fakePages(n int) (pageFetcher, *int) {
	calls := 0
	return func(after string, limit int) (*api.ExportResponse, error) {
		calls++
		start := 0
		if after != "" {
			fmt.Sscanf(after, "%d", &start)
		}
		end := start + limit
		if end > n {
			end = n
		}

		resp := &api.ExportResponse{
			GeneratedAt: "1",
			Sessions:    []api.ExportSession{},
		}
		for i := start; i < end; i++ {
			resp.Sessions = append(resp.Sessions, api.ExportSession{
				SessionID: fmt.Sprintf("s-%d", i),
				StartMS:   int64(i),
			})
		}
		resp.SessionCount = len(resp.Sessions)
		if resp.SessionCount == limit {
			cursor := fmt.Sprintf("%d", end)
			resp.NextCursor = &cursor
		}
		return resp, nil
	}, &calls
}

// The full dump must stay one well-formed object with every session in it,
// even though it is now assembled from many pages.
func TestStreamExportProducesOneValidObjectAcrossPages(t *testing.T) {
	const total = exportPageSize*2 + 137

	fetch, calls := fakePages(total)
	var buf bytes.Buffer
	if err := streamExport(&buf, "1700000000000", fetch); err != nil {
		t.Fatalf("streamExport: %v", err)
	}

	var got api.ExportResponse
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("response is not valid JSON: %v\nfirst 200 bytes: %s", err, buf.String()[:200])
	}

	if got.SessionCount != total {
		t.Errorf("session_count = %d, want %d", got.SessionCount, total)
	}
	if len(got.Sessions) != total {
		t.Errorf("got %d sessions, want %d", len(got.Sessions), total)
	}
	if got.GeneratedAt != "1700000000000" {
		t.Errorf("generated_at = %q, want the value passed in", got.GeneratedAt)
	}
	if *calls != 3 {
		t.Errorf("fetched %d pages, want 3", *calls)
	}

	for i := range got.Sessions {
		if want := fmt.Sprintf("s-%d", i); got.Sessions[i].SessionID != want {
			t.Fatalf("session %d = %q, want %q (pages were not concatenated in order)", i, got.Sessions[i].SessionID, want)
		}
	}
}

func TestStreamExportWithNoSessionsIsStillValidJSON(t *testing.T) {
	fetch, _ := fakePages(0)
	var buf bytes.Buffer
	if err := streamExport(&buf, "1", fetch); err != nil {
		t.Fatalf("streamExport: %v", err)
	}

	var got api.ExportResponse
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("empty export is not valid JSON: %v (%s)", err, buf.String())
	}
	if got.SessionCount != 0 || len(got.Sessions) != 0 {
		t.Errorf("expected an empty export, got %d sessions", len(got.Sessions))
	}
}

// A page boundary landing exactly on the last session returns a cursor, so the
// loop makes one more (empty) fetch. That must not emit a trailing comma.
func TestStreamExportHandlesAnExactPageBoundary(t *testing.T) {
	fetch, calls := fakePages(exportPageSize)
	var buf bytes.Buffer
	if err := streamExport(&buf, "1", fetch); err != nil {
		t.Fatalf("streamExport: %v", err)
	}

	var got api.ExportResponse
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if got.SessionCount != exportPageSize {
		t.Errorf("session_count = %d, want %d", got.SessionCount, exportPageSize)
	}
	if *calls != 2 {
		t.Errorf("fetched %d pages, want 2 (one full page, then the empty confirmation)", *calls)
	}
}

func TestStreamExportStopsOnAFetchError(t *testing.T) {
	want := fmt.Errorf("postgres is down")
	err := streamExport(&bytes.Buffer{}, "1", func(string, int) (*api.ExportResponse, error) {
		return nil, want
	})
	if err == nil {
		t.Fatal("expected the fetch error to surface")
	}
}
