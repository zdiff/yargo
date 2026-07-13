package scanner

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/sansecio/yargo/ast"
	"github.com/sansecio/yargo/parser"
	"github.com/wasilibs/go-re2/experimental"
)

func BenchmarkCompileStringLiterals(b *testing.B) {
	// 50 rules × 5 strings = 250 patterns, representative of a real ruleset.
	rules := make([]*ast.Rule, 50)
	for i := range rules {
		strs := make([]*ast.StringDef, 5)
		for j := range strs {
			strs[j] = &ast.StringDef{
				Name:  fmt.Sprintf("$s%d", j),
				Value: ast.TextString{Value: fmt.Sprintf("pattern_rule%d_str%d", i, j)},
			}
		}
		rules[i] = &ast.Rule{
			Name:      fmt.Sprintf("rule%d", i),
			Strings:   strs,
			Condition: ast.AnyOf{Pattern: "them"},
		}
	}
	rs := &ast.RuleSet{Rules: rules}

	for b.Loop() {
		_, err := Compile(rs)
		if err != nil {
			b.Fatalf("Compile() error = %v", err)
		}
	}
}

func BenchmarkCompileRegexPatterns(b *testing.B) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "rule1",
				Strings: []*ast.StringDef{
					{Name: "$a", Value: ast.RegexString{Pattern: `https?://[^\s]+`}},
					{Name: "$b", Value: ast.RegexString{Pattern: `password\s*=\s*"[^"]+"`}},
				},
				Condition: ast.AnyOf{Pattern: "them"},
			},
			{
				Name: "rule2",
				Strings: []*ast.StringDef{
					{Name: "$a", Value: ast.RegexString{Pattern: `eval\s*\(`}},
					{Name: "$b", Value: ast.RegexString{Pattern: `base64.+decode`}},
				},
				Condition: ast.AnyOf{Pattern: "them"},
			},
		},
	}

	for b.Loop() {
		_, err := Compile(rs)
		if err != nil {
			b.Fatalf("Compile() error = %v", err)
		}
	}
}

func BenchmarkScanStringLiterals(b *testing.B) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "rule1",
				Strings: []*ast.StringDef{
					{Name: "$a", Value: ast.TextString{Value: "malware"}},
					{Name: "$b", Value: ast.TextString{Value: "virus"}},
					{Name: "$c", Value: ast.TextString{Value: "trojan"}},
				},
				Condition: ast.AnyOf{Pattern: "them"},
			},
			{
				Name: "rule2",
				Strings: []*ast.StringDef{
					{Name: "$a", Value: ast.TextString{Value: "eval("}},
					{Name: "$b", Value: ast.TextString{Value: "base64_decode"}},
					{Name: "$c", Value: ast.TextString{Value: "exec("}},
				},
				Condition: ast.AnyOf{Pattern: "them"},
			},
		},
	}

	rules, err := Compile(rs)
	if err != nil {
		b.Fatalf("Compile() error = %v", err)
	}

	// Generate test data - 1MB of sample data with some matches
	data := make([]byte, 1024*1024)
	copy(data[1000:], []byte("This file contains malware"))
	copy(data[5000:], []byte("eval($_POST['cmd'])"))
	copy(data[100000:], []byte("Some virus detected"))

	b.SetBytes(int64(len(data)))

	for b.Loop() {
		var matches MatchRules
		err := rules.ScanMem(data, 0, 30*time.Second, &matches)
		if err != nil {
			b.Fatalf("ScanMem() error = %v", err)
		}
	}
}

func BenchmarkScanRegexPatterns(b *testing.B) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "rule1",
				Strings: []*ast.StringDef{
					{Name: "$a", Value: ast.RegexString{Pattern: `https?://[^\s]+`}},
					{Name: "$b", Value: ast.RegexString{Pattern: `password\s*=\s*"[^"]+"`}},
				},
				Condition: ast.AnyOf{Pattern: "them"},
			},
			{
				Name: "rule2",
				Strings: []*ast.StringDef{
					{Name: "$a", Value: ast.RegexString{Pattern: `eval\s*\(`}},
				},
				Condition: ast.AnyOf{Pattern: "them"},
			},
		},
	}

	rules, err := Compile(rs)
	if err != nil {
		b.Fatalf("Compile() error = %v", err)
	}

	// Generate test data - 1MB of sample data with some matches
	data := make([]byte, 1024*1024)
	copy(data[1000:], []byte("visit https://example.com/path"))
	copy(data[5000:], []byte(`password = "secret123"`))
	copy(data[100000:], []byte("eval (something)"))

	b.SetBytes(int64(len(data)))

	for b.Loop() {
		var matches MatchRules
		err := rules.ScanMem(data, 0, 30*time.Second, &matches)
		if err != nil {
			b.Fatalf("ScanMem() error = %v", err)
		}
	}
}

func BenchmarkScanMixed(b *testing.B) {
	rs := &ast.RuleSet{
		Rules: []*ast.Rule{
			{
				Name: "mixed_rule",
				Strings: []*ast.StringDef{
					{Name: "$literal", Value: ast.TextString{Value: "malware"}},
					{Name: "$regex", Value: ast.RegexString{Pattern: `eval\s*\(`}},
					{Name: "$url", Value: ast.RegexString{Pattern: `https?://[^\s]+`}},
				},
				Condition: ast.AnyOf{Pattern: "them"},
			},
		},
	}

	rules, err := Compile(rs)
	if err != nil {
		b.Fatalf("Compile() error = %v", err)
	}

	// Generate test data
	data := make([]byte, 1024*1024)
	copy(data[1000:], []byte("This file contains malware"))
	copy(data[5000:], []byte("eval (something)"))
	copy(data[100000:], []byte("visit https://example.com"))

	b.SetBytes(int64(len(data)))

	for b.Loop() {
		var matches MatchRules
		err := rules.ScanMem(data, 0, 30*time.Second, &matches)
		if err != nil {
			b.Fatalf("ScanMem() error = %v", err)
		}
	}
}

func BenchmarkFindIndexRecovery(b *testing.B) {
	re, err := experimental.CompileLatin1(`eval\s*\(`)
	if err != nil {
		b.Fatal(err)
	}
	buf := []byte("some text eval (something) more text")

	b.Run("direct", func(b *testing.B) {
		for b.Loop() {
			re.FindIndex(buf)
		}
	})
	b.Run("recover", func(b *testing.B) {
		for b.Loop() {
			recoverFindIndex(re, buf)
		}
	})
}

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

// BenchmarkScanManyHits models the common real-world shape: strings that hit
// constantly, in rules whose conditions almost always fail because a second,
// rarer string is absent. Every one of those hits is collected and thrown away.
func BenchmarkScanManyHits(b *testing.B) {
	common := []string{"function", "return", "require", "module", "exports", "document"}

	var sb strings.Builder
	for i, w := range common {
		fmt.Fprintf(&sb, `
rule noisy_%d {
	strings:
		$common = "%s"
		$rare = "nEvErApPeArS_%d"
	condition:
		$common and $rare
}`, i, w, i)
	}

	rs, err := parser.New().Parse(sb.String())
	if err != nil {
		b.Fatal(err)
	}
	rules, err := Compile(rs)
	if err != nil {
		b.Fatal(err)
	}
	buf := benchBuf()

	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		var m MatchRules
		if err := rules.ScanMem(buf, 0, time.Minute, &m); err != nil {
			b.Fatal(err)
		}
		if len(m) != 0 {
			b.Fatalf("expected no matches, got %d", len(m))
		}
	}
}
