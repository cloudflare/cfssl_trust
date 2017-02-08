package release

import (
	"testing"
	"time"
)

type parseTest struct {
	s string
	r Release
}

var parseTests = []parseTest{
	{s: "2016.2.2", r: Release{Year: 2016, Month: 2, Iteration: 2}},
	{s: "2016.3.0", r: Release{Year: 2016, Month: 3, Iteration: 0}},
	{s: "2016.3.1", r: Release{Year: 2016, Month: 3, Iteration: 1}},
	{s: "2016.3.2", r: Release{Year: 2016, Month: 3, Iteration: 2}},
	{s: "2016.4.0", r: Release{Year: 2016, Month: 4, Iteration: 0}},
	{s: "2016.4.1", r: Release{Year: 2016, Month: 4, Iteration: 1}},
	{s: "2016.4.2", r: Release{Year: 2016, Month: 4, Iteration: 2}},
	{s: "2017.1.0", r: Release{Year: 2017, Month: 1, Iteration: 0}},
	{s: "2017.1.1-g7fdd9a3-dev", r: Release{Year: 2017, Month: 1, Iteration: 1, Extra: "g7fdd9a3-dev"}},
}

var badReleases = []string{
	"v0.5",
	"v0.5.1",
}

// TestString validates the Stringer and Parse functions.
func TestString(t *testing.T) {
	for _, tc := range parseTests {
		rel, err := Parse(tc.s)
		if err != nil {
			t.Fatal(err)
		}

		s := rel.String()
		if s != tc.s {
			t.Fatalf("release: String() returned %s, but should have returned %s",
				s, tc.s)
		}

		cmp := rel.Cmp(tc.r)
		if cmp != 0 {
			t.Logf("release: Cmp() should return 0, but returned %d", cmp)
			t.Logf("release: test case was '%#v', parsed was '%#v'", tc.r, rel)
			t.Error()
		}
	}

	for _, br := range badReleases {
		if _, err := Parse(br); err == nil {
			t.Fatalf("release: %s should be a bad release")
		}
	}
}

const (
	// The indicies are named for clarity.
	relFirst = iota
	relSecond
	relThird
	relNewMonth
	relNewYear
)

type bumpTest struct {
	a, b Release   // a is the initial version, b is the bumped version
	t    time.Time // the timestamp to use for the bump
}

var bumpTests = map[int]bumpTest{
	// The first release happens at the beginning of the month.
	relFirst: bumpTest{
		a: Release{Year: 2016, Month: 11, Iteration: 0},
		b: Release{Year: 2016, Month: 11, Iteration: 1},
		t: time.Date(2016, time.November, 1, 13, 15, 0, 0, time.Local),
	},

	// The second release happens an hour later.
	relSecond: bumpTest{
		a: Release{Year: 2016, Month: 11, Iteration: 1},
		b: Release{Year: 2016, Month: 11, Iteration: 2},
		t: time.Date(2016, time.November, 1, 14, 12, 58, 0, time.Local),
	},

	// The third release happens a few weeks later.
	relThird: bumpTest{
		a: Release{Year: 2016, Month: 11, Iteration: 2},
		b: Release{Year: 2016, Month: 11, Iteration: 3},
		t: time.Date(2016, time.November, 18, 15, 34, 0, 0, time.Local),
	},

	// The fourth release happens the next month (a few weeks
	// after the third release).
	relNewMonth: bumpTest{
		a: Release{Year: 2016, Month: 11, Iteration: 3},
		b: Release{Year: 2016, Month: 12, Iteration: 0},
		t: time.Date(2016, time.December, 6, 11, 41, 19, 0, time.Local),
	},

	// The last release happens the next year.
	relNewYear: bumpTest{
		a: Release{Year: 2016, Month: 12, Iteration: 0},
		b: Release{Year: 2017, Month: 1, Iteration: 0},
		t: time.Date(2017, time.January, 6, 11, 41, 19, 0, time.Local),
	},
}

// TestIncrement verifies that incrementing a release works as
// expected.
func TestIncrement(t *testing.T) {
	// This release is older than this package. It should always
	// fail, unless the clock on the testing machine is months out
	// of date.
	old := Release{Year: 2017, Month: 1, Iteration: 0}
	rel, err := old.Inc()
	if err != nil {
		t.Fatal(err)
	}

	if rel.Cmp(old) != 1 {
		t.Fatal("release: incremented release is not newer than old release")
	}

	// Verify the test cases: incrementing the 'a' release at the
	// timestamp in the test case should result in the 'b'
	// release. The 'b' release should also be newer than the 'a'
	// release, at least as seen by Cmp().
	for _, tc := range bumpTests {
		rel, err := tc.a.IncAt(tc.t)
		if err != nil {
			t.Log(tc.a)
			t.Log(tc.b)
			t.Log(rel)
			t.Fatal(err)
		}

		if rel.Cmp(tc.b) != 0 {
			t.Fatalf("release: increment should have returned %s, but returned %s",
				tc.b, rel)
		}

		cmp := rel.Cmp(tc.a)
		if cmp != 1 {
			t.Log("release: Cmp() returned %d, but it should have returned 1", cmp)
			t.Error("release: this indicates that the incremented release does not represent a later release.")
		}
	}
}

func TestRegression(t *testing.T) {
	rel := Release{Year: 2017, Month: 1, Iteration: 0}
	at := time.Date(2016, time.January, 6, 11, 41, 19, 0, time.Local)

	_, err := rel.IncAt(at)
	if err == nil {
		t.Fatal("release: inc() should have signaled a regression")
	}
}
