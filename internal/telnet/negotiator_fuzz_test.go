package telnet

import "testing"

func FuzzFeed(f *testing.F) {
	f.Add([]byte("root\r\n"), 2)
	f.Add([]byte{IAC, SB, OptTTYPE, ttypeIs, 'x', IAC, SE}, 3)
	f.Add([]byte{IAC, WILL, OptTTYPE, IAC, DO, 34, IAC, IAC, '\r', 0}, 1)
	f.Fuzz(func(t *testing.T, in []byte, split int) {
		n := NewNegotiator()
		n.Initial()
		if split < 0 || split > len(in) {
			split = len(in) / 2
		}
		d1, r1 := n.Feed(in[:split])
		d2, r2 := n.Feed(in[split:])
		if len(d1)+len(d2) > len(in) {
			t.Fatalf("data %d bytes > input %d bytes", len(d1)+len(d2), len(in))
		}
		if len(r1)+len(r2) > 3*len(in)+9 {
			t.Fatalf("reply %d bytes for %d input bytes", len(r1)+len(r2), len(in))
		}
		if len(n.sb) > maxSubnegotiation {
			t.Fatalf("sb buffer %d > cap %d", len(n.sb), maxSubnegotiation)
		}
		if len(n.Meta().ClientWill) > maxRecordedOptions {
			t.Fatalf("ClientWill %d > cap", len(n.Meta().ClientWill))
		}
		if len(n.Meta().TerminalType) > maxTerminalType {
			t.Fatalf("TerminalType %d bytes > cap", len(n.Meta().TerminalType))
		}
	})
}
