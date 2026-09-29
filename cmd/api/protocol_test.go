package main

import (
	"net/http/httptest"
	"testing"

	"github.com/mirage-source/mirage-core/internal/session"
)

func TestProtocolParam(t *testing.T) {
	for query, want := range map[string]session.Protocol{"": session.ProtocolSSH, "?protocol=ssh": session.ProtocolSSH, "?protocol=telnet": session.ProtocolTelnet} {
		w := httptest.NewRecorder()
		got, ok := protocolParam(w, httptest.NewRequest("GET", "/api/stats"+query, nil))
		if !ok || got != want || w.Code != 200 {
			t.Errorf("%q -> (%q, %v, %d), want (%q, true, 200)", query, got, ok, w.Code, want)
		}
	}
	w := httptest.NewRecorder()
	if _, ok := protocolParam(w, httptest.NewRequest("GET", "/api/stats?protocol=rdp", nil)); ok || w.Code != 400 {
		t.Errorf("rdp -> ok=%v code=%d, want false 400", ok, w.Code)
	}
}
