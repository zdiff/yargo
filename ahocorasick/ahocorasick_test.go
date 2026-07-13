package ahocorasick

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"sync"
	"testing"
)

func buildAC(patterns ...string) AhoCorasick {
	builder := NewAhoCorasickBuilder()
	bytePatterns := make([][]byte, len(patterns))
	for i, p := range patterns {
		bytePatterns[i] = []byte(p)
	}
	return builder.BuildByte(bytePatterns)
}

func collectMatches(ac AhoCorasick, haystack string) []Match {
	iter := ac.IterOverlappingByte([]byte(haystack))
	var matches []Match
	for next := iter.Next(); next != nil; next = iter.Next() {
		matches = append(matches, *next)
	}
	return matches
}

func TestIterOverlapping_SinglePattern(t *testing.T) {
	ac := buildAC("abc")
	matches := collectMatches(ac, "xxabcxxabcxx")

	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(matches))
	}
	if matches[0].Start() != 2 || matches[0].End() != 5 {
		t.Errorf("match 0: expected [2,5), got [%d,%d)", matches[0].Start(), matches[0].End())
	}
	if matches[1].Start() != 7 || matches[1].End() != 10 {
		t.Errorf("match 1: expected [7,10), got [%d,%d)", matches[1].Start(), matches[1].End())
	}
}

func TestIterOverlapping_MultiplePatterns(t *testing.T) {
	ac := buildAC("he", "she", "his", "hers")
	matches := collectMatches(ac, "ushers")

	if len(matches) < 3 {
		t.Fatalf("expected at least 3 overlapping matches, got %d", len(matches))
	}

	found := make(map[int]bool)
	for _, m := range matches {
		found[m.Pattern()] = true
	}
	if !found[0] {
		t.Error("expected to find pattern 'he'")
	}
	if !found[1] {
		t.Error("expected to find pattern 'she'")
	}
	if !found[3] {
		t.Error("expected to find pattern 'hers'")
	}
}

func TestIterOverlapping_NoMatch(t *testing.T) {
	ac := buildAC("foo", "bar")
	matches := collectMatches(ac, "nothing here")

	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d", len(matches))
	}
}

func TestIterOverlapping_EmptyHaystack(t *testing.T) {
	ac := buildAC("abc")
	matches := collectMatches(ac, "")

	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d", len(matches))
	}
}

func TestIterOverlapping_SubstringPatterns(t *testing.T) {
	ac := buildAC("a", "ab", "abc")
	matches := collectMatches(ac, "abc")

	if len(matches) != 3 {
		t.Fatalf("expected 3 overlapping matches, got %d", len(matches))
	}
}

func TestIterOverlapping_Parallel(t *testing.T) {
	ac := buildAC("bear", "masha")
	haystack := []byte("The bear and masha")

	var w sync.WaitGroup
	w.Add(50)
	for range 50 {
		go func() {
			defer w.Done()
			iter := ac.IterOverlappingByte(haystack)
			var count int
			for next := iter.Next(); next != nil; next = iter.Next() {
				count++
			}
			if count != 2 {
				t.Errorf("expected 2 matches, got %d", count)
			}
		}()
	}
	w.Wait()
}

// bruteForceFold finds every case-insensitive occurrence of each pattern.
func bruteForceFold(patterns [][]byte, haystack []byte) []string {
	var out []string
	for pi, p := range patterns {
		for i := 0; i+len(p) <= len(haystack); i++ {
			if strings.EqualFold(string(haystack[i:i+len(p)]), string(p)) {
				out = append(out, fmt.Sprintf("%d@%d", pi, i))
			}
		}
	}
	slices.Sort(out)
	return out
}

func TestAsciiCaseFoldMatchesBruteForce(t *testing.T) {
	// small sets keep the prefilter active, large sets disable it —
	// both paths must fold the haystack identically
	patternSets := [][][]byte{
		{[]byte("abc")},
		{[]byte("aB"), []byte("Ab")},
		{[]byte("she"), []byte("he"), []byte("hers"), []byte("his")},
		{[]byte("GetProcAddress"), []byte("eval"), []byte("\x01\x02Z"), []byte("Zz")},
	}
	alphabet := []byte("aAbBcCzZeEhHsSrRgG\x00\x01\x02 ")
	rng := rand.New(rand.NewPCG(7, 11))

	var sawPrefilter bool
	for si, patterns := range patternSets {
		builder := NewAhoCorasickBuilder()
		builder.AsciiCaseFold(true)
		ac := builder.BuildByte(patterns)
		sawPrefilter = sawPrefilter || ac.i.prefil != nil

		for range 200 {
			haystack := make([]byte, rng.IntN(64))
			for i := range haystack {
				haystack[i] = alphabet[rng.IntN(len(alphabet))]
			}

			var got []string
			iter := ac.IterOverlappingByte(haystack)
			for m := iter.Next(); m != nil; m = iter.Next() {
				got = append(got, fmt.Sprintf("%d@%d", m.Pattern(), m.Start()))
			}
			slices.Sort(got)

			want := bruteForceFold(patterns, haystack)
			if !slices.Equal(got, want) {
				t.Fatalf("set %d, haystack %q:\n got %v\nwant %v", si, haystack, got, want)
			}
		}
	}

	if !sawPrefilter {
		t.Error("no pattern set built a prefilter, so the folded prefilter path went untested")
	}
}
