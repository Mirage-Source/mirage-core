package main

import (
	"errors"
	"testing"
	"time"

	"github.com/mirage-source/mirage-core/internal/api"
	"github.com/mirage-source/mirage-core/internal/session"
)

func TestStatsCacheEmptyUntilRefreshed(t *testing.T) {
	c := &statsCache{}
	if _, _, ok := c.get(session.ProtocolSSH); ok {
		t.Fatal("empty cache reported a value")
	}
}

func TestStatsCacheRefreshLoadsEveryProtocolInOrder(t *testing.T) {
	c := &statsCache{}
	at := time.Date(2026, 11, 3, 5, 0, 0, 0, time.UTC)
	var order []session.Protocol
	c.refresh(func(p session.Protocol) (*api.HoneypotStats, error) {
		order = append(order, p)
		return &api.HoneypotStats{TotalSessions: uint64(len(order))}, nil
	}, func() time.Time { return at })

	if len(order) != 2 || order[0] != session.ProtocolSSH || order[1] != session.ProtocolTelnet {
		t.Fatalf("load order = %v, want [ssh telnet] one after the other", order)
	}
	got, when, ok := c.get(session.ProtocolTelnet)
	if !ok || got.TotalSessions != 2 || !when.Equal(at) {
		t.Fatalf("telnet = (%v, %v, %v)", got, when, ok)
	}
}

func TestStatsCacheKeepsLastGoodValueWhenRefreshFails(t *testing.T) {
	c := &statsCache{}
	t0 := time.Date(2026, 11, 3, 5, 0, 0, 0, time.UTC)
	c.refresh(func(session.Protocol) (*api.HoneypotStats, error) {
		return &api.HoneypotStats{TotalSessions: 7}, nil
	}, func() time.Time { return t0 })

	c.refresh(func(p session.Protocol) (*api.HoneypotStats, error) {
		if p == session.ProtocolSSH {
			return nil, errors.New("timeout")
		}
		return &api.HoneypotStats{TotalSessions: 9}, nil
	}, func() time.Time { return t0.Add(time.Hour) })

	ssh, at, _ := c.get(session.ProtocolSSH)
	if ssh.TotalSessions != 7 || !at.Equal(t0) {
		t.Errorf("ssh = (%d, %v), want the old value (7, %v)", ssh.TotalSessions, at, t0)
	}
	// One protocol failing must not stop the other from refreshing.
	tel, _, _ := c.get(session.ProtocolTelnet)
	if tel.TotalSessions != 9 {
		t.Errorf("telnet = %d, want 9", tel.TotalSessions)
	}
}
