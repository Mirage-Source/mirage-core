package telnet

const (
	SE   byte = 240
	SB   byte = 250
	WILL byte = 251
	WONT byte = 252
	DO   byte = 253
	DONT byte = 254
	IAC  byte = 255
)

const (
	OptEcho  byte = 1
	OptSGA   byte = 3
	OptTTYPE byte = 24
	OptNAWS  byte = 31
)

const (
	ttypeIs   byte = 0
	ttypeSend byte = 1
)

const maxSubnegotiation = 64

const maxRecordedOptions = 32

const maxTerminalType = 40

type state int

const (
	stateData state = iota
	stateIAC
	stateOption
	stateSB
	stateSBIAC
)

type Meta struct {
	Negotiated   bool
	ClientWill   []byte
	TerminalType string
	WindowWidth  int
	WindowHeight int
}

type Negotiator struct {
	st         state
	verb       byte
	sb         []byte
	sbOverflow bool
	afterCR    bool

	weWill map[byte]bool
	weDo   map[byte]bool

	ttypeRequested bool
	meta           Meta
}

func NewNegotiator() *Negotiator {
	return &Negotiator{
		weWill: map[byte]bool{},
		weDo:   map[byte]bool{},
	}
}

func (n *Negotiator) Initial() []byte {
	n.weWill[OptEcho] = true
	n.weWill[OptSGA] = true
	n.weDo[OptTTYPE] = true
	n.weDo[OptNAWS] = true
	return []byte{
		IAC, WILL, OptEcho,
		IAC, WILL, OptSGA,
		IAC, DO, OptTTYPE,
		IAC, DO, OptNAWS,
	}
}

func (n *Negotiator) Meta() Meta {
	m := n.meta
	m.ClientWill = append([]byte(nil), n.meta.ClientWill...)
	return m
}

func (n *Negotiator) Feed(in []byte) (data, reply []byte) {
	for _, b := range in {
		switch n.st {
		case stateData:
			if b == IAC {
				n.st = stateIAC
				continue
			}
			if n.afterCR && b == 0 {
				n.afterCR = false
				continue
			}
			n.afterCR = b == '\r'
			data = append(data, b)

		case stateIAC:
			n.meta.Negotiated = true
			switch b {
			case IAC:
				data = append(data, IAC)
				n.afterCR = false
				n.st = stateData
			case WILL, WONT, DO, DONT:
				n.verb = b
				n.st = stateOption
			case SB:
				n.sb = n.sb[:0]
				n.sbOverflow = false
				n.st = stateSB
			default:
				n.st = stateData
			}

		case stateOption:
			reply = append(reply, n.negotiate(n.verb, b)...)
			n.st = stateData

		case stateSB:
			if b == IAC {
				n.st = stateSBIAC
				continue
			}
			n.appendSB(b)

		case stateSBIAC:
			switch b {
			case SE:
				n.finishSB()
				n.st = stateData
			case IAC:
				n.appendSB(IAC)
				n.st = stateSB
			default:
				n.st = stateSB
			}
		}
	}
	return data, reply
}

func (n *Negotiator) appendSB(b byte) {
	if len(n.sb) >= maxSubnegotiation {
		n.sbOverflow = true
		return
	}
	n.sb = append(n.sb, b)
}

func (n *Negotiator) negotiate(verb, opt byte) []byte {
	switch verb {
	case DO:
		if opt == OptEcho || opt == OptSGA {
			if n.weWill[opt] {
				return nil
			}
			n.weWill[opt] = true
			return []byte{IAC, WILL, opt}
		}
		return []byte{IAC, WONT, opt}

	case DONT:
		if n.weWill[opt] {
			n.weWill[opt] = false
			return []byte{IAC, WONT, opt}
		}
		return nil

	case WILL:
		n.recordWill(opt)
		if opt == OptTTYPE || opt == OptNAWS {
			var out []byte
			if !n.weDo[opt] {
				n.weDo[opt] = true
				out = append(out, IAC, DO, opt)
			}
			if opt == OptTTYPE && !n.ttypeRequested {
				n.ttypeRequested = true
				out = append(out, IAC, SB, OptTTYPE, ttypeSend, IAC, SE)
			}
			return out
		}
		return []byte{IAC, DONT, opt}

	case WONT:
		n.weDo[opt] = false
		return nil
	}
	return nil
}

func (n *Negotiator) recordWill(opt byte) {
	for _, o := range n.meta.ClientWill {
		if o == opt {
			return
		}
	}
	if len(n.meta.ClientWill) < maxRecordedOptions {
		n.meta.ClientWill = append(n.meta.ClientWill, opt)
	}
}

func (n *Negotiator) finishSB() {
	if n.sbOverflow || len(n.sb) == 0 {
		return
	}
	switch n.sb[0] {
	case OptTTYPE:
		if len(n.sb) >= 2 && n.sb[1] == ttypeIs {
			n.meta.TerminalType = sanitize(n.sb[2:], maxTerminalType)
		}
	case OptNAWS:
		if len(n.sb) >= 5 {
			n.meta.WindowWidth = int(n.sb[1])<<8 | int(n.sb[2])
			n.meta.WindowHeight = int(n.sb[3])<<8 | int(n.sb[4])
		}
	}
}

func sanitize(b []byte, max int) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c < 0x20 || c > 0x7E {
			continue
		}
		if len(out) == max {
			break
		}
		out = append(out, c)
	}
	return string(out)
}
