// Package release implements versioning.
package release

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// New returns a release for the current year and month with a zero
// iteration counter.
func New() Release {
	now := time.Now()

	return Release{
		Year:  now.Year(),
		Month: int(now.Month()),
	}
}

// Releases use a YYYY-MM-IT form, where IT is the current iteration
// of the package this month. Extra allows for additional information
// (such as "-dirty") in the release.
type Release struct {
	Year      int
	Month     int
	Iteration int
	Extra     string
}

// String satisfies the Stringer interface.
func (r Release) String() string {
	s := fmt.Sprintf("%04d.%d.%d", r.Year, r.Month, r.Iteration)
	if r.Extra != "" {
		s += "-" + r.Extra
	}

	return s
}

// Cmp compares two releases. It returns -1 if r is an older release
// than o, 0 if they are the same release, and 1 if r is a later
// release. If the releases are the same except for extra (which is
// typically a git hash and some other tag), there isn't a way to
// determine which release comes first, so the return value will be
// -1.
func (r Release) Cmp(o Release) int {
	if r.Year < o.Year {
		return -1
	} else if r.Year > o.Year {
		return 1
	}

	if r.Month < o.Month {
		return -1
	} else if r.Month > o.Month {
		return 1
	}

	if r.Iteration < o.Iteration {
		return -1
	} else if r.Iteration > o.Iteration {
		return 1
	}

	if r.Extra == "" {
		if o.Extra != "" {
			return -1
		}
	}

	if o.Extra == "" {
		if r.Extra != "" {
			return 1
		}
	}

	if r.Extra != "" && o.Extra != "" {
		if r.Extra != o.Extra {
			return -1
		}
	}

	return 0
}

// Inc increments the release. If the year or month has changed,
// the iteration counter is reset. No extra tags are assigned.
func (r Release) Inc() (Release, error) {
	return r.IncAt(time.Now())
}

// IncAt increments the release assuming the given timestamp. This is
// useful for verifying increments.
func (r Release) IncAt(now time.Time) (Release, error) {
	year := now.Year()
	month := int(now.Month())

	rel := Release{
		Year:      r.Year,
		Month:     r.Month,
		Iteration: r.Iteration,
		Extra:     r.Extra,
	}

	if r.Year > year {
		return rel, errors.New("release: incremented release caused a regression (year)")
	}

	if r.Year == year && r.Month > month {
		return rel, errors.New("release: incremented release caused a regression (month)")
	}

	if year != rel.Year {
		rel.Year = year
		rel.Month = month
		rel.Iteration = 0
	} else if month != rel.Month {
		rel.Month = month
		rel.Iteration = 0
	} else {
		rel.Iteration++
	}

	return rel, nil
}

// Parse takes a version string and returns a release structure.
func Parse(in string) (Release, error) {
	var rel Release
	parts := strings.Split(in, ".")
	if len(parts) != 3 {
		return rel, errors.New("release: invalid release " + in)
	}

	var err error
	rel.Year, err = strconv.Atoi(parts[0])
	if err != nil {
		return rel, err
	}

	rel.Month, err = strconv.Atoi(parts[1])
	if err != nil {
		return rel, err
	}

	parts = strings.SplitN(parts[2], "-", 2)
	rel.Iteration, err = strconv.Atoi(parts[0])
	if err != nil {
		return rel, err
	}

	if len(parts) == 2 {
		rel.Extra = parts[1]
	}

	return rel, nil
}
