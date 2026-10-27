package shell

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Number handling that matches Ubuntu 22.04's mawk 1.3.4 20200120, whose integers are 32 bits wide
// ("maximum-integer 2147483647" in `awk -W version`): a whole number prints as an integer only within
// ±2147483647 and goes through CONVFMT/OFMT (%.6g) beyond that, and %d clamps there.
const awkMaxInt = 2147483647

func awkIsSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r'
}

// awkNumStr is a number as a string. Whole numbers in range print as integers; anything else uses fmtSpec
// (CONVFMT when concatenating, OFMT when printing).
func awkNumStr(d float64, fmtSpec string) string {
	switch {
	case math.IsNaN(d):
		if math.Signbit(d) {
			return "-nan"
		}
		return "nan"
	case math.IsInf(d, 1):
		return "inf"
	case math.IsInf(d, -1):
		return "-inf"
	case d == math.Trunc(d) && d >= -awkMaxInt && d <= awkMaxInt:
		return strconv.FormatInt(int64(d), 10)
	}
	return awkSprintf(fmtSpec, []awkVal{num(d)}, nil)
}

// awkStrtod is C's strtod over a string: leading white space, a sign, then inf, infinity, nan, a hex
// number (0x1f) or a decimal one, the longest prefix that parses. n is how much of s it used (0: none).
func awkStrtod(s string) (v float64, n int) {
	i := 0
	for i < len(s) && awkIsSpace(s[i]) {
		i++
	}
	neg := false
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		neg = s[i] == '-'
		i++
	}
	rest := strings.ToLower(s[i:])
	var mag float64
	switch {
	case strings.HasPrefix(rest, "infinity"):
		mag, i = math.Inf(1), i+8
	case strings.HasPrefix(rest, "inf"):
		mag, i = math.Inf(1), i+3
	case strings.HasPrefix(rest, "nan"):
		mag, i = math.NaN(), i+3
	case strings.HasPrefix(rest, "0x") && len(rest) > 2 && (isHexDigit(rest[2]) || (rest[2] == '.' && len(rest) > 3 && isHexDigit(rest[3]))):
		j := 2
		var m float64
		digits := 0
		for j < len(rest) && isHexDigit(rest[j]) {
			m, digits, j = m*16+float64(hexVal(rest[j])), digits+1, j+1
		}
		exp := 0
		if j < len(rest) && rest[j] == '.' {
			j++
			for j < len(rest) && isHexDigit(rest[j]) {
				m, exp, digits, j = m*16+float64(hexVal(rest[j])), exp-4, digits+1, j+1
			}
		}
		if j < len(rest) && rest[j] == 'p' {
			k := j + 1
			if k < len(rest) && (rest[k] == '+' || rest[k] == '-') {
				k++
			}
			if k < len(rest) && rest[k] >= '0' && rest[k] <= '9' {
				e, _ := strconv.Atoi(rest[j+1 : scanDigits(rest, k)])
				exp += e
				j = scanDigits(rest, k)
			}
		}
		mag, i = math.Ldexp(m, exp), i+j
	default:
		j := scanDecimal(rest)
		if j == 0 {
			return 0, 0
		}
		mag, _ = strconv.ParseFloat(rest[:j], 64) // ±Inf on overflow, which is what strtod gives too
		i += j
	}
	if neg {
		mag = -mag
	}
	return mag, i
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	}
	return int(c-'A') + 10
}

func scanDigits(s string, i int) int {
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return i
}

// scanDecimal is the length of the decimal floating-point number at the start of s: digits, an optional
// fraction, an optional exponent. 0 when there are no digits.
func scanDecimal(s string) int {
	i := scanDigits(s, 0)
	digits := i
	if i < len(s) && s[i] == '.' {
		j := scanDigits(s, i+1)
		digits += j - i - 1
		i = j
	}
	if digits == 0 {
		return 0
	}
	if i < len(s) && (s[i] == 'e' || s[i] == 'E') {
		j := i + 1
		if j < len(s) && (s[j] == '+' || s[j] == '-') {
			j++
		}
		if k := scanDigits(s, j); k > j {
			i = k
		}
	}
	return i
}

// awkToNum is awk's string-to-number: the strtod prefix, 0 when there is none.
func awkToNum(s string) float64 {
	v, _ := awkStrtod(s)
	return v
}

// awkLooksNumeric decides whether input text (a field, a getline result, a -v value) compares as a number.
// It is stricter than strtod: decimal only, white space allowed around it, and only lowercase inf and nan
// (optionally negative) of the special values, as mawk's scanner has it.
func awkLooksNumeric(s string) (float64, bool) {
	i, j := 0, len(s)
	for i < j && awkIsSpace(s[i]) {
		i++
	}
	for j > i && awkIsSpace(s[j-1]) {
		j--
	}
	t := s[i:j]
	if t == "" {
		return 0, false
	}
	switch t {
	case "inf":
		return math.Inf(1), true
	case "-inf":
		return math.Inf(-1), true
	case "nan":
		return math.NaN(), true
	case "-nan":
		return math.Copysign(math.NaN(), -1), true
	}
	k := 0
	if t[0] == '+' || t[0] == '-' {
		k = 1
	}
	if h := t[k:]; len(h) > 2 && h[0] == '0' && (h[1] == 'x' || h[1] == 'X') {
		// hex counts only when its digits are 0-9: "0x10" does, "0x1f" does not
		j := scanDigits(h, 2)
		digits := j - 2
		if j < len(h) && h[j] == '.' {
			e := scanDigits(h, j+1)
			digits += e - j - 1
			j = e
		}
		if j < len(h) && (h[j] == 'p' || h[j] == 'P') {
			e := j + 1
			if e < len(h) && (h[e] == '+' || h[e] == '-') {
				e++
			}
			if f := scanDigits(h, e); f > e {
				j = f
			}
		}
		if digits == 0 || j != len(h) {
			return 0, false
		}
		v, _ := awkStrtod(t)
		return v, true
	}
	if n := scanDecimal(t[k:]); n == 0 || k+n != len(t) {
		return 0, false
	}
	v, _ := strconv.ParseFloat(t, 64)
	return v, true
}

// awkSprintf formats like mawk's sprintf. numFmt is unused here; it is the receiver-free entry the
// runtime and awkNumStr share. rt, when not nil, reports a bad format to the caller through rt.fail.
func awkSprintf(format string, args []awkVal, rt *awkRT) string {
	var b strings.Builder
	ai := 0
	next := func() (awkVal, bool) {
		if ai < len(args) {
			ai++
			return args[ai-1], true
		}
		return awkVal{}, false
	}
	for i := 0; i < len(format); i++ {
		c := format[i]
		if c != '%' {
			b.WriteByte(c)
			continue
		}
		if i+1 < len(format) && format[i+1] == '%' {
			b.WriteByte('%')
			i++
			continue
		}
		j := i + 1
		flags := ""
		for j < len(format) && strings.IndexByte("-+ #0", format[j]) >= 0 {
			flags += string(format[j])
			j++
		}
		width, prec := "", ""
		if j < len(format) && format[j] == '*' {
			if v, ok := next(); ok {
				w := int(clampInt(v.num()))
				if w < 0 {
					flags += "-"
					w = -w
				}
				width = strconv.Itoa(w)
			}
			j++
		} else {
			k := scanDigits(format, j)
			width, j = format[j:k], k
		}
		hasPrec := false
		if j < len(format) && format[j] == '.' {
			hasPrec = true
			j++
			if j < len(format) && format[j] == '*' {
				if v, ok := next(); ok {
					prec = strconv.Itoa(int(clampInt(v.num())))
				}
				j++
			} else {
				k := scanDigits(format, j)
				prec, j = format[j:k], k
			}
			if prec == "" {
				prec = "0"
			}
		}
		for j < len(format) && strings.IndexByte("hlLqjzt", format[j]) >= 0 {
			j++ // length modifiers mean nothing here
		}
		if j >= len(format) {
			b.WriteString(format[i:]) // a lone % or an unfinished spec is printed as it is
			break
		}
		conv := format[j]
		spec := "%" + flags + width
		if hasPrec {
			spec += "." + prec
		}
		arg, have := next()
		switch conv {
		case 'd', 'i':
			if !have {
				rt.failf("not enough arguments passed to %s(\"%s\")", rt.fn(), format)
			}
			b.WriteString(fmt.Sprintf(spec+"d", int64(clampInt(arg.num()))))
		case 'o', 'x', 'X', 'u':
			if !have {
				rt.failf("not enough arguments passed to %s(\"%s\")", rt.fn(), format)
			}
			verb := string(conv)
			if conv == 'u' {
				verb = "d"
			}
			u := awkToUint(arg.num())
			if u == 0 {
				spec = strings.ReplaceAll(spec, "#", "") // C prints a bare 0
			}
			b.WriteString(fmt.Sprintf(spec+verb, u))
		case 'e', 'E', 'f', 'F', 'g', 'G':
			if !have {
				rt.failf("not enough arguments passed to %s(\"%s\")", rt.fn(), format)
			}
			b.WriteString(awkFloat(spec, conv, hasPrec, arg.num()))
		case 'c':
			if !have {
				rt.failf("not enough arguments passed to %s(\"%s\")", rt.fn(), format)
			}
			var ch string
			if arg.isNum {
				ch = string([]byte{byte(int64(clampInt(arg.num())))})
			} else if s := arg.str(); s != "" {
				ch = s[:1]
			} else {
				ch = "\x00" // C's %c of the string's terminating NUL
			}
			b.WriteString(fmt.Sprintf("%"+flags+width+"s", ch))
		case 's':
			if !have {
				rt.failf("not enough arguments passed to %s(\"%s\")", rt.fn(), format)
			}
			b.WriteString(fmt.Sprintf(spec+"s", arg.str()))
		default:
			rt.failf("bad conversion in %s(\"%s\")", rt.fn(), format)
		}
		i = j
	}
	return b.String()
}

// clampInt is C's d_to_I for this build: truncate, and stay inside ±2147483647 (NaN is 0).
func clampInt(d float64) int64 {
	switch {
	case math.IsNaN(d):
		return 0
	case d >= awkMaxInt:
		return awkMaxInt
	case d <= -awkMaxInt:
		return -awkMaxInt
	}
	return int64(d)
}

// awkToUint is the conversion for %o %x %X %u.
func awkToUint(d float64) uint64 {
	switch {
	case math.IsNaN(d):
		return 0
	case d >= 4294967295:
		return 4294967295
	case d <= 0:
		return 0
	}
	return uint64(d)
}

// awkFloat is C's %e %f %g, which Go spells differently for infinities, NaN and the default %g precision.
func awkFloat(spec string, conv byte, hasPrec bool, d float64) string {
	if math.IsInf(d, 0) || math.IsNaN(d) {
		s := "inf"
		if math.IsNaN(d) {
			s = "nan"
		}
		sign := ""
		if math.Signbit(d) {
			sign = "-"
		} else if strings.Contains(spec, "+") {
			sign = "+"
		} else if strings.Contains(spec, " ") {
			sign = " "
		}
		if conv >= 'A' && conv <= 'Z' {
			s = strings.ToUpper(s)
		}
		s = sign + s
		// width applies, padded with spaces on the left (or the right with -)
		w := 0
		if k := strings.IndexByte(spec, '.'); k >= 0 {
			spec = spec[:k]
		}
		digits := strings.TrimLeft(spec, "%-+ #0")
		w, _ = strconv.Atoi(digits)
		if strings.Contains(spec, "-") {
			return fmt.Sprintf("%-*s", w, s)
		}
		return fmt.Sprintf("%*s", w, s)
	}
	if (conv == 'g' || conv == 'G') && !hasPrec {
		spec += ".6"
	}
	if conv == 'F' {
		conv = 'f'
	}
	return fmt.Sprintf(spec+string(conv), d)
}

func (rt *awkRT) fn() string {
	if rt == nil || rt.fmtFn == "" {
		return "sprintf"
	}
	return rt.fmtFn
}
