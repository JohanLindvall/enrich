package enrich

import (
	"math/rand"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

// slowValidTraceID is the original per-byte implementation, kept as the oracle
// for the SWAR fast path in validTraceID (the same pattern severity_test.go
// uses for the severity LUT).
func slowValidTraceID(s string) bool {
	if len(s) < 32 || len(s) > 36 {
		return false
	}
	hex, zeros := 0, 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case isHex(c):
			hex++
			if c == '0' {
				zeros++
			}
		case c != '-':
			return false
		}
	}
	return hex == 32 && zeros != 32
}

// slowValidSpanID is the original per-byte span-ID check, as the oracle for
// the SWAR fast path.
func slowValidSpanID(s string) bool {
	if len(s) != 16 {
		return false
	}
	zeros := 0
	for i := 0; i < len(s); i++ {
		if !isHex(s[i]) {
			return false
		}
		if s[i] == '0' {
			zeros++
		}
	}
	return zeros != 16
}

// TestHex8Exhaustive pins hex8's per-lane classification: every byte value, in
// every lane, against isHex.
func TestHex8Exhaustive(t *testing.T) {
	for c := 0; c < 256; c++ {
		for lane := 0; lane < 8; lane++ {
			b := []byte("00000000")
			b[lane] = byte(c)
			w := le64(string(b), 0)
			assert.Equal(t, isHex(byte(c)), hex8(w), "byte %#x in lane %d", c, lane)
		}
	}
}

// TestValidIDsMatchSlow differential-tests the SWAR trace/span validators
// against the per-byte originals: shapes seen in the wild, adversarial edge
// cases, and a randomized sweep over an alphabet that includes near-hex bytes
// (g, G, '/', ':', '`', 0x80, ...) chosen to sit just outside the hex ranges.
func TestValidIDsMatchSlow(t *testing.T) {
	cases := []string{
		"", "0", "-",
		"aabbccdd11223344556677889900aabb",     // valid 32-hex
		"AABBCCDD11223344556677889900AABB",     // uppercase
		"00000000000000000000000000000000",     // all-zero: invalid
		"0000000000000000000000000000000g",     // non-hex tail
		"g0000000000000000000000000000000",     // non-hex head
		"aabbccdd-1122-3344-5566-77889900aabb", // dashed UUID form
		"00000000-0000-0000-0000-000000000000", // all-zero dashed
		"aabbccdd-1122-3344-5566-77889900aab",  // 35: too few hex
		"aabbccdd112233445566778899_0aabb",     // '_' is not a dash
		strings.Repeat("a", 31), strings.Repeat("a", 33), strings.Repeat("a", 37),
		"aabbccdd1122334455667788",                  // 24
		"aabbccdd11223344",                          // valid span
		"AABBCCDD11223344",                          // uppercase span
		"0000000000000000",                          // all-zero span
		"aabbccdd1122334g",                          // non-hex span
		"aabbccdd112233440",                         // 17
		"aabbccdd1122334",                           // 15
		"\x800000000000000000000000000000000"[0:32], // high bit head
	}
	for _, s := range cases {
		assert.Equal(t, slowValidTraceID(s), validTraceID(s), "trace %q", s)
		assert.Equal(t, slowValidSpanID(s), validSpanID(s), "span %q", s)
	}

	const alphabet = "0123456789abcdefABCDEF-gG/:`@\x00\x80\xff \tzZ"
	rng := rand.New(rand.NewSource(2))
	buf := make([]byte, 0, 40)
	for i := 0; i < 200000; i++ {
		buf = buf[:0]
		// Cluster lengths around the interesting 15..37 window, biased heavily
		// toward hex digits so valid shapes are actually generated.
		n := 14 + rng.Intn(24)
		for j := 0; j < n; j++ {
			if rng.Intn(8) == 0 {
				buf = append(buf, alphabet[rng.Intn(len(alphabet))])
			} else {
				buf = append(buf, "0123456789abcdef"[rng.Intn(16)])
			}
		}
		s := string(buf)
		assert.Equal(t, slowValidTraceID(s), validTraceID(s), "trace %q", s)
		assert.Equal(t, slowValidSpanID(s), validSpanID(s), "span %q", s)
	}
}

// TestLowerMatchesToLower differential-tests lower against strings.ToLower:
// real resource-ID shapes, the ASCII boundary bytes around A-Z ('@', '[', '`',
// '{'), non-ASCII bytes at every position class (head, SWAR body, byte tail),
// and a randomized sweep.
func TestLowerMatchesToLower(t *testing.T) {
	cases := []string{
		"", "A", "a", "@", "[", "`", "{", "\x80", "é",
		"/SUBSCRIPTIONS/11111111-1111-1111-1111-111111111111/RESOURCEGROUPS/SHOP/PROVIDERS/MICROSOFT.WEB/SITES/ORDERS-API",
		"/subscriptions/11111111-1111-1111-1111-111111111111/resourcegroups/shop",
		"already lowercase, stays aliased",
		"MIXED case WITH Tail-Bytes-1234567", // length not a multiple of 8
		"ABCDEFG",                            // shorter than one word
		"AAAAAAAAé",                          // non-ASCII in the byte tail
		"AAAAAAA\xc3\xa9AAAAAAAA",            // non-ASCII inside a SWAR word
		"aaaaaaa\xffZZZZZZZZ",                // stray high byte inside a word
	}
	for _, s := range cases {
		assert.Equal(t, strings.ToLower(s), lower(s), "lower(%q)", s)
	}

	rng := rand.New(rand.NewSource(3))
	const chars = "AZaz@[`{/-.09\x7f\x80\xc3\xa9 _"
	buf := make([]byte, 0, 64)
	for i := 0; i < 200000; i++ {
		buf = buf[:0]
		for n := rng.Intn(40); n > 0; n-- {
			buf = append(buf, chars[rng.Intn(len(chars))])
		}
		s := string(buf)
		assert.Equal(t, strings.ToLower(s), lower(s), "lower(%q)", s)
	}

	// The alias case: an already-lowercase input must be returned as is, not
	// copied — callers rely on the no-alloc property.
	in := "/subscriptions/x/resourcegroups/y"
	assert.Same(t, unsafe.StringData(in), unsafe.StringData(lower(in)))
}
