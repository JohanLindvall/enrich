package enrich

import "unsafe"

// unsafeString views b as a string. Callers guarantee b is never mutated
// while the view is reachable — everywhere in this package, b aliases the
// immutable input line.
func unsafeString(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}

// SWAR (SIMD-within-a-register) hex classification. validTraceID and
// validSpanID run on every line that carries a trace/span/request-ID field —
// the per-byte isHex loop was ~5% of the JSON path — and their dominant shape
// is a dashless run of 16 or 32 hex digits, which these helpers decide eight
// bytes at a time. Unlike the logfmt package's scan masks, every formula here
// is exact per byte (no borrow can cross a lane), because validation needs
// "all bytes pass", not "find the first stop".
//
// hex_test.go differential-tests the fast functions against the plain
// per-byte implementations they replaced, over exhaustive 1-2 byte inputs and
// a randomized sweep.

const (
	swarLanes = 0x0101010101010101 // 0x01 in every byte
	swarHigh  = 0x8080808080808080 // 0x80 in every byte
	swarLow7  = 0x7f7f7f7f7f7f7f7f
	swarZero  = 0x3030303030303030 // '0' in every byte
	swarCase  = 0x2020202020202020 // the ASCII case bit
)

// le64 assembles eight bytes of s into one word. The or-chain is the load
// pattern the compiler combines into a single unaligned load on amd64/arm64;
// every user below is lane-local or whole-word-equality, so the byte order
// within the word never matters.
func le64(s string, i int) uint64 {
	s = s[i : i+8]
	return uint64(s[0]) | uint64(s[1])<<8 | uint64(s[2])<<16 | uint64(s[3])<<24 |
		uint64(s[4])<<32 | uint64(s[5])<<40 | uint64(s[6])<<48 | uint64(s[7])<<56
}

// putLE64 stores w into b[i:i+8] with the byte order le64 reads; the
// assignment chain is the store pattern the compiler combines into one write.
func putLE64(b []byte, i int, w uint64) {
	b = b[i : i+8]
	b[0], b[1], b[2], b[3] = byte(w), byte(w>>8), byte(w>>16), byte(w>>24)
	b[4], b[5], b[6], b[7] = byte(w>>32), byte(w>>40), byte(w>>48), byte(w>>56)
}

// laneRange flags (0x80 in that lane) every byte of v that lies in [lo, hi].
// v must have all high bits clear (bytes <= 0x7f); lo and hi are ASCII. Both
// the "+ (0x80-lo)" and "+ (0x7f-hi)" sums stay below 0x100 per lane under
// that precondition, so no carry ever crosses a lane and the result is exact.
func laneRange(v uint64, lo, hi byte) uint64 {
	ge := (v + swarLanes*uint64(0x80-lo)) & swarHigh // byte >= lo
	gt := (v + swarLanes*uint64(0x7f-hi)) & swarHigh // byte > hi
	return ge &^ gt
}

// hex8 reports whether all eight bytes of w are ASCII hex digits.
func hex8(w uint64) bool {
	if w&swarHigh != 0 {
		return false // non-ASCII byte; also makes the masked sums below exact
	}
	digits := laneRange(w, '0', '9')
	letters := laneRange(w|swarCase, 'a', 'f') // the fold maps only A-F onto a-f
	return (digits | letters) == swarHigh
}

// hexRun reports whether s[i:i+n] is entirely ASCII hex digits and whether it
// is entirely '0'. n must be a multiple of 8.
func hexRun(s string, i, n int) (isHex, isZero bool) {
	isZero = true
	for end := i + n; i < end; i += 8 {
		w := le64(s, i)
		if !hex8(w) {
			return false, false
		}
		isZero = isZero && w == swarZero
	}
	return true, isZero
}
