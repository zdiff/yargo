// Package scanner provides YARA rule scanning using Aho-Corasick algorithm.
package scanner

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/sansecio/yargo/ahocorasick"

	"github.com/sansecio/yargo/ast"
)

type (
	// Regexp is the interface for a compiled regular expression.
	// It is satisfied by *regexp.Regexp from the standard library,
	// go-re2, and coregex.
	Regexp interface {
		FindIndex(b []byte) []int
	}

	// CompileFunc compiles a regex pattern string into a Regexp.
	CompileFunc func(string) (Regexp, error)

	// ScanFlags controls scanning behavior.
	ScanFlags int

	// ScanCallback is the interface for receiving match notifications.
	ScanCallback interface {
		RuleMatching(r *MatchRule) (abort bool, err error)
	}

	// MatchString represents a matched string within a rule.
	MatchString struct {
		Name string
		Data []byte
	}

	// Meta represents a metadata entry from a rule.
	Meta struct {
		Identifier string
		Value      any
	}

	// MatchRule represents a rule that matched during scanning.
	MatchRule struct {
		Rule    string
		Metas   []Meta
		Strings []MatchString
	}

	// MatchRules collects matching rules and implements ScanCallback.
	MatchRules []MatchRule

	// Rules holds compiled YARA rules ready for scanning.
	Rules struct {
		rules         []*compiledRule
		matcher       *ahocorasick.AhoCorasick
		patterns      [][]byte
		patternMap    []patternRef
		regexPatterns []*regexPattern
	}
)

type (
	// patternRef maps a pattern index back to its source rule and string.
	patternRef struct {
		ruleIndex   int
		stringIndex int
		fullword    bool
		regexIdx    int
	}

	// regexPattern holds a lazily compiled regex for complex regex matching.
	regexPattern struct {
		pattern     string
		compile     CompileFunc
		once        sync.Once
		re          Regexp
		ruleIndex   int
		stringIndex int
		fullword    bool
	}

	// compiledRule holds the compiled form of a single YARA rule.
	compiledRule struct {
		name        string
		metas       []Meta
		condition   ast.Expr
		stringNames []string
	}

	// matchInfo records the position and length of a single pattern match.
	// The matched bytes are only copied out of the scanned buffer for rules
	// whose condition passes.
	matchInfo struct {
		pos int
		len int
	}
)

// maxMatchLen is the window size around atom hits used for regex verification.
const maxMatchLen = 1024

// Meta returns the value of the meta field with the given identifier, or nil.
func (m *MatchRule) Meta(identifier string) any {
	for _, meta := range m.Metas {
		if meta.Identifier == identifier {
			return meta.Value
		}
	}
	return nil
}

// MetaString returns the string value of the meta field, or defValue if missing or not a string.
func (m *MatchRule) MetaString(identifier, defValue string) string {
	if val, ok := m.Meta(identifier).(string); ok {
		return val
	}
	return defValue
}

// RuleMatching implements ScanCallback, collecting all matching rules.
func (m *MatchRules) RuleMatching(r *MatchRule) (abort bool, err error) {
	*m = append(*m, *r)
	return false, nil
}

// Stats returns compilation statistics.
func (r *Rules) Stats() (acPatterns, regexPatterns int) {
	return len(r.patterns), len(r.regexPatterns)
}

// NumRules returns the number of compiled rules.
func (r *Rules) NumRules() int {
	return len(r.rules)
}

func isWordChar(b byte) bool {
	return (b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') ||
		b == '_'
}

func checkWordBoundary(buf []byte, start, end int) bool {
	if start > 0 && isWordChar(buf[start-1]) {
		return false
	}
	if end < len(buf) && isWordChar(buf[end]) {
		return false
	}
	return true
}

// ScanMem scans a byte buffer for matching rules. A timeout of zero or less
// means no timeout.
func (r *Rules) ScanMem(buf []byte, flags ScanFlags, timeout time.Duration, cb ScanCallback) error {
	if r.matcher == nil && len(r.regexPatterns) == 0 {
		return nil
	}

	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	ruleMatches, err := r.collectMatches(ctx, buf)
	if err != nil {
		return err
	}
	return r.evaluateRules(ctx, buf, ruleMatches, cb)
}

// ctxCheckInterval is how many AC matches (or regex verification windows)
// are processed between context cancellation checks.
const ctxCheckInterval = 4096

// collectMatches runs AC matching, atom-based regex verification, and full-scan
// regex to collect all match positions per rule and string index.
func (r *Rules) collectMatches(ctx context.Context, buf []byte) (map[int]map[int][]matchInfo, error) {
	ruleMatches := make(map[int]map[int][]matchInfo)
	atomCandidates := make(map[int][]int)

	if r.matcher != nil {
		iter := r.matcher.IterOverlappingByte(buf)
		steps := 0
		for match := iter.Next(); match != nil; match = iter.Next() {
			steps++
			if steps%ctxCheckInterval == 0 && ctx.Err() != nil {
				return nil, ctx.Err()
			}
			ref := r.patternMap[match.Pattern()]

			if ref.regexIdx >= 0 {
				atomCandidates[ref.regexIdx] = append(atomCandidates[ref.regexIdx], match.Start())
				continue
			}

			if ref.fullword && !checkWordBoundary(buf, match.Start(), match.End()) {
				continue
			}

			addMatch(ruleMatches, ref.ruleIndex, ref.stringIndex, match.Start(), match.End()-match.Start())
		}
	}

	halfWindow := maxMatchLen / 2
	windows := 0
	for regexIdx, positions := range atomCandidates {
		rp := r.regexPatterns[regexIdx]
		re := rp.compiled()
		if re == nil {
			continue
		}
		positions = dedupe(positions)

		// Verify a window around every candidate position, recording each
		// distinct match. Candidates inside an already verified match are
		// skipped and windows start after it (non-overlapping, like RE2's
		// FindAll), so the same match is never reported twice.
		lastEnd := 0
		for _, pos := range positions {
			if pos < lastEnd {
				continue
			}
			windows++
			if windows%ctxCheckInterval == 0 && ctx.Err() != nil {
				return nil, ctx.Err()
			}
			start := max(max(0, pos-halfWindow), lastEnd)
			end := min(len(buf), pos+halfWindow)

			loc := recoverFindIndex(re, buf[start:end])
			if loc == nil {
				continue
			}
			matchStart := start + loc[0]
			matchEnd := start + loc[1]
			lastEnd = matchEnd
			if rp.fullword && !checkWordBoundary(buf, matchStart, matchEnd) {
				continue
			}
			addMatch(ruleMatches, rp.ruleIndex, rp.stringIndex, matchStart, matchEnd-matchStart)
		}
	}

	return ruleMatches, nil
}

// evaluateRules evaluates conditions for rules with matches, invokes the
// callback for matching rules, and handles abort/timeout.
func (r *Rules) evaluateRules(ctx context.Context, buf []byte, ruleMatches map[int]map[int][]matchInfo, cb ScanCallback) error {
	ruleIndices := make([]int, 0, len(ruleMatches))
	for ruleIdx := range ruleMatches {
		ruleIndices = append(ruleIndices, ruleIdx)
	}
	slices.Sort(ruleIndices)

	for _, ruleIdx := range ruleIndices {
		matchedStrings := ruleMatches[ruleIdx]
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		cr := r.rules[ruleIdx]

		matchPositions := make(map[int][]int, len(matchedStrings))
		for idx, infos := range matchedStrings {
			positions := make([]int, len(infos))
			for i, info := range infos {
				positions[i] = info.pos
			}
			matchPositions[idx] = positions
		}

		evalCtx := &evalContext{
			matches:     matchPositions,
			buf:         buf,
			stringNames: cr.stringNames,
		}
		if !evalExpr(cr.condition, evalCtx) {
			continue
		}

		stringIndices := make([]int, 0, len(matchedStrings))
		for idx := range matchedStrings {
			stringIndices = append(stringIndices, idx)
		}
		slices.Sort(stringIndices)

		strings := make([]MatchString, 0, len(matchedStrings))
		for _, idx := range stringIndices {
			name := cr.stringNames[idx]
			for _, info := range matchedStrings[idx] {
				data := make([]byte, info.len)
				copy(data, buf[info.pos:info.pos+info.len])
				strings = append(strings, MatchString{Name: name, Data: data})
			}
		}

		abort, err := cb.RuleMatching(&MatchRule{
			Rule:    cr.name,
			Metas:   cr.metas,
			Strings: strings,
		})
		if err != nil {
			return err
		}
		if abort {
			return nil
		}
	}

	return nil
}

// ScanFile scans a file for matching rules.
// The implementation is platform-specific:
//   - Unix (Linux, macOS, BSD): uses mmap for zero-copy file scanning
//   - Windows: uses CreateFileMapping/MapViewOfFile for native memory mapping
//   - WASM (js): not supported — use [Rules.ScanMem] with file content instead
//
// See scanfile_unix.go, scanfile_windows.go, and scanfile_js.go.

func addMatch(m map[int]map[int][]matchInfo, ruleIdx int, stringIndex int, pos int, length int) {
	if m[ruleIdx] == nil {
		m[ruleIdx] = make(map[int][]matchInfo)
	}
	m[ruleIdx][stringIndex] = append(m[ruleIdx][stringIndex], matchInfo{pos: pos, len: length})
}

// compiled returns the compiled Regexp, compiling it on first use.
// If compilation fails, it returns nil.
func (rp *regexPattern) compiled() Regexp {
	rp.once.Do(func() {
		re, err := rp.compile(rp.pattern)
		if err == nil {
			rp.re = re
		}
	})
	return rp.re
}

// recoverFindIndex wraps Regexp.FindIndex to recover from panics.
// go-re2's WASM backend can panic during regex execution (e.g. OOM),
// so we treat a panic as no match.
func recoverFindIndex(re Regexp, b []byte) (loc []int) {
	defer func() {
		if r := recover(); r != nil {
			loc = nil
		}
	}()
	return re.FindIndex(b)
}

func dedupe(positions []int) []int {
	if len(positions) <= 1 {
		return positions
	}
	slices.Sort(positions)
	j := 1
	for i := 1; i < len(positions); i++ {
		if positions[i] != positions[j-1] {
			positions[j] = positions[i]
			j++
		}
	}
	return positions[:j]
}
