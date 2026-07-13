package scanner

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/sansecio/yargo/parser"
)

// benchRules builds a ruleset that looks like a real malware corpus: mostly
// case-sensitive text strings, some hex, a few regexes, and (optionally) a
// handful of nocase strings.
func benchRules(tb testing.TB, nocase bool) *Rules {
	var sb strings.Builder
	for i := range 200 {
		mods := ""
		if nocase && i%20 == 0 {
			mods = " nocase"
		}
		fmt.Fprintf(&sb, `
rule text_%d {
	strings:
		$a = "GetProcAddress_%d"%s
		$b = "eval(base64_decode_%d"
	condition:
		any of them
}`, i, i, mods, i)
	}
	for i := range 40 {
		fmt.Fprintf(&sb, `
rule hex_%d {
	strings:
		$a = { 4D 5A 90 %02X 03 00 00 00 }
	condition:
		$a
}`, i, i)
	}
	for i := range 20 {
		fmt.Fprintf(&sb, `
rule re_%d {
	strings:
		$a = /passthru_%d\([^)]{0,32}\)/
	condition:
		$a
}`, i, i)
	}

	rs, err := parser.New().Parse(sb.String())
	if err != nil {
		tb.Fatal(err)
	}
	rules, err := CompileWithOptions(rs, CompileOptions{SkipInvalidRegex: true})
	if err != nil {
		tb.Fatal(err)
	}
	return rules
}

// benchBuf builds a 1 MiB buffer of source-code-like text with a few planted hits.
func benchBuf() []byte {
	rng := rand.New(rand.NewPCG(1, 2))
	words := []string{
		"function", "return", "if", "else", "var", "const", "require",
		"module", "exports", "window", "document", "GetProcAddr", "Eval",
		"echo", "printf", "malloc", "free", "struct", "static", "inline",
	}
	var sb strings.Builder
	for sb.Len() < 1<<20 {
		sb.WriteString(words[rng.IntN(len(words))])
		if rng.IntN(8) == 0 {
			sb.WriteByte('\n')
		} else {
			sb.WriteByte(' ')
		}
	}
	sb.WriteString(" GetProcAddress_7 passthru_3(x) ")
	return []byte(sb.String())
}

func benchScan(b *testing.B, nocase bool) {
	rules := benchRules(b, nocase)
	buf := benchBuf()

	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		var m MatchRules
		if err := rules.ScanMem(buf, 0, time.Minute, &m); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkScanNoNocase(b *testing.B) { benchScan(b, false) }
func BenchmarkScanNocase(b *testing.B)   { benchScan(b, true) }
