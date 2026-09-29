package telnet

import (
	"bytes"
	"strings"
	"testing"
)

func feedAll(n *Negotiator, chunks ...[]byte) (data, reply []byte) {
	for _, c := range chunks {
		d, r := n.Feed(c)
		data = append(data, d...)
		reply = append(reply, r...)
	}
	return data, reply
}

func TestPlainTextPassesThrough(t *testing.T) {
	n := NewNegotiator()
	data, reply := n.Feed([]byte("root\r\n"))
	if string(data) != "root\r\n" {
		t.Errorf("data = %q, want %q", data, "root\r\n")
	}
	if len(reply) != 0 {
		t.Errorf("reply = %v, want none", reply)
	}
	if n.Meta().Negotiated {
		t.Error("Negotiated = true for a client that sent no IAC")
	}
}

func TestEscapedIACIsDataByte(t *testing.T) {
	n := NewNegotiator()
	data, _ := n.Feed([]byte{'a', IAC, IAC, 'b'})
	if !bytes.Equal(data, []byte{'a', 0xFF, 'b'}) {
		t.Errorf("data = %v, want [a 0xFF b]", data)
	}
}

func TestCRNULBecomesCR(t *testing.T) {
	n := NewNegotiator()
	data, _ := n.Feed([]byte{'l', 's', '\r', 0x00})
	if string(data) != "ls\r" {
		t.Errorf("data = %q, want %q", data, "ls\r")
	}
}

func TestInitialOffersEchoAndSGAAndAsksTTYPEAndNAWS(t *testing.T) {
	n := NewNegotiator()
	want := []byte{
		IAC, WILL, OptEcho,
		IAC, WILL, OptSGA,
		IAC, DO, OptTTYPE,
		IAC, DO, OptNAWS,
	}
	if got := n.Initial(); !bytes.Equal(got, want) {
		t.Errorf("Initial() = %v, want %v", got, want)
	}
}

func TestAcknowledgementsGetNoReply(t *testing.T) {
	n := NewNegotiator()
	n.Initial()
	_, reply := n.Feed([]byte{IAC, DO, OptEcho, IAC, DO, OptSGA})
	if len(reply) != 0 {
		t.Errorf("reply to ack = %v, want none", reply)
	}
}

func TestUnsupportedDOIsRefused(t *testing.T) {
	n := NewNegotiator()
	n.Initial()
	const optLinemode = 34
	_, reply := n.Feed([]byte{IAC, DO, optLinemode})
	if want := []byte{IAC, WONT, optLinemode}; !bytes.Equal(reply, want) {
		t.Errorf("reply = %v, want %v", reply, want)
	}
}

func TestUnsupportedWILLIsRefusedAndRecorded(t *testing.T) {
	n := NewNegotiator()
	n.Initial()
	const optNewEnviron = 39
	_, reply := n.Feed([]byte{IAC, WILL, optNewEnviron})
	if want := []byte{IAC, DONT, optNewEnviron}; !bytes.Equal(reply, want) {
		t.Errorf("reply = %v, want %v", reply, want)
	}
	if got := n.Meta().ClientWill; !bytes.Equal(got, []byte{optNewEnviron}) {
		t.Errorf("ClientWill = %v, want [%d]", got, optNewEnviron)
	}
	if !n.Meta().Negotiated {
		t.Error("Negotiated = false after the client sent IAC WILL")
	}
}

func TestClientWillTTYPETriggersSendRequest(t *testing.T) {
	n := NewNegotiator()
	n.Initial()
	_, reply := n.Feed([]byte{IAC, WILL, OptTTYPE})
	want := []byte{IAC, SB, OptTTYPE, ttypeSend, IAC, SE}
	if !bytes.Equal(reply, want) {
		t.Errorf("reply = %v, want %v", reply, want)
	}
}

func TestTTYPEIsSubnegotiationRecorded(t *testing.T) {
	n := NewNegotiator()
	n.Initial()
	in := append([]byte{IAC, SB, OptTTYPE, ttypeIs}, "XTERM-256COLOR"...)
	in = append(in, IAC, SE)
	data, _ := n.Feed(in)
	if len(data) != 0 {
		t.Errorf("subnegotiation leaked into data: %q", data)
	}
	if got := n.Meta().TerminalType; got != "XTERM-256COLOR" {
		t.Errorf("TerminalType = %q, want XTERM-256COLOR", got)
	}
}

func TestNAWSRecordsWindowSize(t *testing.T) {
	n := NewNegotiator()
	n.Initial()
	n.Feed([]byte{IAC, SB, OptNAWS, 0, 200, 0, 50, IAC, SE})
	m := n.Meta()
	if m.WindowWidth != 200 || m.WindowHeight != 50 {
		t.Errorf("window = %dx%d, want 200x50", m.WindowWidth, m.WindowHeight)
	}
}

func TestNAWSWithEscaped255(t *testing.T) {
	n := NewNegotiator()
	n.Initial()
	n.Feed([]byte{IAC, SB, OptNAWS, 0, IAC, IAC, 0, 24, IAC, SE})
	if m := n.Meta(); m.WindowWidth != 255 || m.WindowHeight != 24 {
		t.Errorf("window = %dx%d, want 255x24", m.WindowWidth, m.WindowHeight)
	}
}

func TestSequenceSplitAcrossFeedCalls(t *testing.T) {
	n := NewNegotiator()
	n.Initial()
	full := []byte{'a', IAC, SB, OptTTYPE, ttypeIs, 'V', 'T', '1', '0', '0', IAC, SE, 'b'}
	chunks := make([][]byte, len(full))
	for i := range full {
		chunks[i] = full[i : i+1]
	}
	data, _ := feedAll(n, chunks...)
	if string(data) != "ab" {
		t.Errorf("data = %q, want %q", data, "ab")
	}
	if got := n.Meta().TerminalType; got != "VT100" {
		t.Errorf("TerminalType = %q, want VT100", got)
	}
}

func TestUnterminatedSubnegotiationIsCapped(t *testing.T) {
	n := NewNegotiator()
	n.Initial()
	n.Feed([]byte{IAC, SB, OptTTYPE, ttypeIs})
	n.Feed(bytes.Repeat([]byte{'A'}, 1<<20))
	if len(n.sb) > maxSubnegotiation {
		t.Errorf("subnegotiation buffer = %d bytes, cap is %d", len(n.sb), maxSubnegotiation)
	}
	data, _ := n.Feed([]byte{IAC, SE, 'o', 'k'})
	if string(data) != "ok" {
		t.Errorf("data after overflowed SB = %q, want %q", data, "ok")
	}
	if got := n.Meta().TerminalType; got != "" {
		t.Errorf("TerminalType from overflowed SB = %q, want empty", got)
	}
}

func TestTerminalTypeIsSanitized(t *testing.T) {
	n := NewNegotiator()
	n.Initial()
	in := append([]byte{IAC, SB, OptTTYPE, ttypeIs}, "xterm\x1b[31m\x00"...)
	in = append(in, IAC, SE)
	n.Feed(in)
	got := n.Meta().TerminalType
	if strings.ContainsAny(got, "\x1b\x00") {
		t.Errorf("TerminalType kept control bytes: %q", got)
	}
	if got != "xterm[31m" {
		t.Errorf("TerminalType = %q, want %q", got, "xterm[31m")
	}
}

func TestClientWillListIsDedupedAndCapped(t *testing.T) {
	n := NewNegotiator()
	n.Initial()
	var in []byte
	for i := 0; i < 3; i++ {
		in = append(in, IAC, WILL, 39)
	}
	for opt := 100; opt < 200; opt++ {
		in = append(in, IAC, WILL, byte(opt))
	}
	n.Feed(in)
	got := n.Meta().ClientWill
	if len(got) > maxRecordedOptions {
		t.Errorf("ClientWill has %d entries, cap is %d", len(got), maxRecordedOptions)
	}
	if got[0] != 39 || (len(got) > 1 && got[1] == 39) {
		t.Errorf("ClientWill = %v, want 39 recorded once, first", got)
	}
}

func TestTwoByteCommandsAreConsumed(t *testing.T) {
	n := NewNegotiator()
	const nop, ga = 241, 249
	data, reply := n.Feed([]byte{'x', IAC, nop, IAC, ga, 'y'})
	if string(data) != "xy" {
		t.Errorf("data = %q, want %q", data, "xy")
	}
	if len(reply) != 0 {
		t.Errorf("reply = %v, want none", reply)
	}
}

func TestDONTEchoTurnsOffAndIsAcknowledgedOnce(t *testing.T) {
	n := NewNegotiator()
	n.Initial()
	_, reply := n.Feed([]byte{IAC, DONT, OptEcho, IAC, DONT, OptEcho})
	if want := []byte{IAC, WONT, OptEcho}; !bytes.Equal(reply, want) {
		t.Errorf("reply = %v, want %v (acknowledged once)", reply, want)
	}
}
