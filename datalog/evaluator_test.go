package datalog

import (
	"github.com/stretchr/testify/require"
	"slices"
	"testing"
)

func TestCartesianProductIterator(t *testing.T) {
	tests := map[string]struct {
		expected        [][]int
		factsCount      int
		predicatesCount int
		visit           func(int, []int, func(int))
	}{
		"zero predicates": {
			// Zero predicates should still cause one yield to support rules without a body,
			// such as the automatic `allow` policy.
			expected:        [][]int{{}},
			factsCount:      3,
			predicatesCount: 0,
		},
		"zero facts": {
			// Zero facts is treated as an invalid evaluation, yielding nothing.
			expected:        [][]int{},
			factsCount:      0,
			predicatesCount: 3,
		},
		"zero predicates, zero facts": {
			// Zero predicates should still cause one yield to support rules without a body,
			// such as the automatic `allow` policy.
			expected:        [][]int{{}},
			factsCount:      0,
			predicatesCount: 0,
		},
		"one predicate, one fact": {
			expected:        [][]int{{0}},
			factsCount:      1,
			predicatesCount: 1,
		},
		"one predicate, multiple facts": {
			expected:        [][]int{{0}, {1}, {2}},
			factsCount:      3,
			predicatesCount: 1,
		},
		"multiple predicates, one fact": {
			expected:        [][]int{{0, 0, 0}},
			factsCount:      1,
			predicatesCount: 3,
		},
		"two predicates, two facts": {
			expected:        [][]int{{0, 0}, {0, 1}, {1, 0}, {1, 1}},
			factsCount:      2,
			predicatesCount: 2,
		},
		"two predicates, three facts": {
			expected: [][]int{
				{0, 0}, {0, 1}, {0, 2},
				{1, 0}, {1, 1}, {1, 2},
				{2, 0}, {2, 1}, {2, 2}},
			factsCount:      3,
			predicatesCount: 2,
		},
		"three predicates, two facts": {
			expected: [][]int{
				{0, 0, 0}, {0, 0, 1},
				{0, 1, 0}, {0, 1, 1},
				{1, 0, 0}, {1, 0, 1},
				{1, 1, 0}, {1, 1, 1}},
			factsCount:      2,
			predicatesCount: 3,
		},
		"failed match at position 0": {
			expected: [][]int{
				{0, 0},
				{1, 0}, {1, 1}, {1, 2},
				{2, 0}, {2, 1}, {2, 2}},
			factsCount:      3,
			predicatesCount: 2,
			visit: func(i int, ints []int, failAt func(int)) {
				if i == 0 && ints[0] == 0 {
					failAt(0)
				}
			},
		},
		"failed match at position 0 (for facts 0 and 2)": {
			expected: [][]int{
				{0, 0},
				{1, 0}, {1, 1}, {1, 2},
				{2, 0}},
			factsCount:      3,
			predicatesCount: 2,
			visit: func(i int, ints []int, failAt func(int)) {
				if i == 0 && ints[0] == 0 {
					failAt(0)
				}
				if i == 4 && ints[0] == 2 {
					failAt(0)
				}
			},
		},
		"failed match at position 1 with 2 predicates": {
			expected: [][]int{
				{0, 0}, {0, 1}, {0, 2},
				{1, 0}, {1, 1}, {1, 2},
				{2, 0}, {2, 1}, {2, 2}},
			factsCount:      3,
			predicatesCount: 2,
			visit: func(i int, ints []int, failAt func(int)) {
				if i == 1 && ints[1] == 1 {
					failAt(1)
				}
			},
		},
		"failed matches at position 1 and 7 with 3 predicates": {
			expected: [][]int{
				{0, 0, 0}, {0, 0, 1},
				{0, 1, 0}, {0, 1, 1}, {0, 1, 2},
				{0, 2, 0}, {0, 2, 1}, {0, 2, 2},
				{1, 0, 0}, {1, 0, 1}, {1, 0, 2},
				{1, 1, 0},
				{2, 0, 0}, {2, 0, 1}, {2, 0, 2},
				{2, 1, 0}, {2, 1, 1}, {2, 1, 2},
				{2, 2, 0}, {2, 2, 1}, {2, 2, 2},
			},
			factsCount:      3,
			predicatesCount: 3,
			visit: func(i int, ints []int, failAt func(int)) {
				if i == 1 && ints[1] == 0 {
					failAt(1)
				}
				if i == 11 && ints[0] == 1 {
					failAt(0)
				}
			},
		},
		"failed matches for all position n-1": {
			// When there is no "more right" branch to prune, failing in the last position,
			// full iteration is necessary (there is nothing to prune).
			expected: [][]int{
				{0, 0}, {0, 1}, {0, 2},
				{1, 0}, {1, 1}, {1, 2},
				{2, 0}, {2, 1}, {2, 2}},
			factsCount:      3,
			predicatesCount: 2,
			visit: func(i int, ints []int, failAt func(int)) {
				failAt(1)
			},
		},
		"failed matches for middle positions": {
			expected: [][]int{
				{0, 0, 0},
				{0, 1, 0},
				{0, 2, 0},
				{1, 0, 0},
				{1, 1, 0},
				{1, 2, 0},
				{2, 0, 0},
				{2, 1, 0},
				{2, 2, 0},
			},
			factsCount:      3,
			predicatesCount: 3,
			visit: func(i int, ints []int, failAt func(int)) {
				failAt(1)
			},
		},
		"invalid failAt index (off by one)": {
			expected: [][]int{
				{0, 0}, {0, 1}, {0, 2},
				{1, 0}, {1, 1}, {1, 2},
				{2, 0}, {2, 1}, {2, 2}},
			factsCount:      3,
			predicatesCount: 2,
			visit: func(i int, ints []int, failAt func(int)) {
				failAt(2) // out of bounds for predicate length
			},
		},
		"invalid failAt index (large number)": {
			expected: [][]int{
				{0, 0}, {0, 1}, {0, 2},
				{1, 0}, {1, 1}, {1, 2},
				{2, 0}, {2, 1}, {2, 2}},
			factsCount:      3,
			predicatesCount: 2,
			visit: func(i int, ints []int, failAt func(int)) {
				failAt(20) // out of bounds for predicate length
			},
		},
		"negative failAt": {
			expected: [][]int{
				{0, 0}, {0, 1}, {0, 2},
				{1, 0}, {1, 1}, {1, 2},
				{2, 0}, {2, 1}, {2, 2}},
			factsCount:      3,
			predicatesCount: 2,
			visit: func(i int, ints []int, failAt func(int)) {
				failAt(-1)
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			sut := combinations{
				predicateCount: tc.predicatesCount,
				factCount:      tc.factsCount,
			}

			actual := make([][]int, 0, len(tc.expected))
			iterator, failAt := sut.iter()
			i := 0
			for x := range iterator {
				actual = append(actual, slices.Clone(x))
				if tc.visit != nil {
					tc.visit(i, x, failAt)
				}
				i++
			}

			require.Equal(t, tc.expected, actual)
		})
	}
}

func TestCombineItIterator(t *testing.T) {
	const (
		// These simulate symbol table indexes
		// (we don't use a symbol table in this test)
		indexForResource   = 100
		indexForSpam       = 196
		indexForEggs       = 197
		indexForFoo        = 198
		indexForBar        = 199
		indexForRight      = 200
		indexForFile1      = 300
		indexForFile2      = 301
		indexForRead       = 50
		indexForWrite      = 60
		indexForVariableR  = 10
		indexForVariableOp = 20
		indexForVariableX  = 30
	)

	type originAndVariables struct {
		origin    *Origin
		variables matchedVariables
	}

	termPtr := func(term Term) *Term {
		return &term
	}

	tests := map[string]struct {
		expected   []originAndVariables
		predicates []Predicate
		factSet    *FactSet
	}{
		"happy path matching variables": {
			expected: []originAndVariables{
				{
					origin: NewOrigin(0),
					variables: matchedVariables{
						Variable(indexForVariableR):  termPtr(String(indexForFile1)), // $r = "file1"
						Variable(indexForVariableOp): termPtr(String(indexForRead)),  // $op = "read"
					},
				},
				{
					origin: NewOrigin(0),
					variables: matchedVariables{
						Variable(indexForVariableR):  termPtr(String(indexForFile2)), // $r == "file2"
						Variable(indexForVariableOp): termPtr(String(indexForWrite)), // $r == "write"
					},
				},
			},
			predicates: []Predicate{
				{
					Name:  String(indexForResource),            // "resource"
					Terms: []Term{Variable(indexForVariableR)}, // $r
				},
				{
					Name: String(indexForRight), // "right"
					Terms: []Term{
						Variable(indexForVariableR),  // $r
						Variable(indexForVariableOp), // $op
					},
				},
			},
			factSet: NewFactSet(
				*NewOrigin(0),
				Fact{Predicate{
					Name:  String(indexForResource),      // "resource"
					Terms: []Term{String(indexForFile1)}, // "file1"
				}},
				Fact{Predicate{
					Name:  String(indexForResource),      // "resource"
					Terms: []Term{String(indexForFile2)}, // "file2"
				}},
				Fact{Predicate{
					Name: String(indexForRight), // "right"
					Terms: []Term{
						String(indexForFile1), // "file1"
						String(indexForRead),  // "read"
					},
				}},
				Fact{Predicate{
					Name: String(indexForRight), // "right"
					Terms: []Term{
						String(indexForFile2), // "file2"
						String(indexForWrite), // "write"
					},
				}},
			),
		},
		"predicate with no matching fact": {
			expected: []originAndVariables{}, // Empty
			predicates: []Predicate{
				{
					Name:  String(indexForFoo),
					Terms: []Term{},
				},
			},
			factSet: NewFactSet(*NewOrigin(0), Fact{Predicate{
				Name: String(indexForBar), // Different name - no match
			}}),
		},
		"policy with empty query body": {
			expected: []originAndVariables{{
				// This is a valid result, but there at no new facts adding new block IDs.
				origin:    nil,
				variables: matchedVariables{},
			}},
			predicates: []Predicate{}, // No predicates for the rule (empty body)
			factSet: NewFactSet(*NewOrigin(0),
				Fact{Predicate{ // There is at least one fact
					Name: String(indexForFoo),
					Terms: []Term{
						String(indexForBar),
					},
				}},
			),
		},
		"Non-matching predicate": {
			expected: []originAndVariables{},
			predicates: []Predicate{
				{
					Name: String(indexForResource),
				},
			},
			factSet: NewFactSet(*NewOrigin(0), Fact{Predicate{
				Name: String(indexForFile1),
			}}),
		},
		"Variable unification failure": {
			expected: []originAndVariables{}, // $x can't be both "file1" and "file2"
			predicates: []Predicate{
				{
					Name: String(indexForFoo), // "foo"
					Terms: []Term{
						Variable(indexForVariableX), // $x
						String(indexForFile1),       // "file1"
					},
				},
				{
					Name: String(indexForBar), // "bar"
					Terms: []Term{
						Variable(indexForVariableX), // $x
						String(indexForFile1),       // "file2"
					},
				},
			},
			factSet: NewFactSet(*NewOrigin(0),
				Fact{Predicate{
					Name: String(indexForFoo), // "foo"
					Terms: []Term{
						Variable(indexForSpam), // "spam"
						String(indexForFile1),  // "file1"
					},
				}},
				Fact{Predicate{
					Name: String(indexForBar), // "bar"
					Terms: []Term{
						Variable(indexForEggs), // "eggs"
						String(indexForFile2),  // "file2"
					},
				}},
			),
		},
		"Same variable appears twice": {
			expected: []originAndVariables{
				{
					origin: NewOrigin(0),
					variables: matchedVariables{
						Variable(indexForVariableX): termPtr(String(indexForFoo)),
					},
				},
			},
			predicates: []Predicate{
				{
					Name: String(indexForSpam),
					Terms: []Term{
						Variable(indexForVariableX),
						Variable(indexForVariableX),
					},
				},
			},
			factSet: NewFactSet(*NewOrigin(0),
				Fact{Predicate{
					Name: String(indexForSpam),
					Terms: []Term{
						String(indexForFoo),
						String(indexForFoo),
					},
				}},
				Fact{Predicate{
					Name: String(indexForSpam),
					Terms: []Term{
						String(indexForFoo),
						String(indexForBar),
					},
				}},
			),
		},
		"Union of origins from multiple facts": {
			expected: []originAndVariables{
				{
					origin:    NewOrigin(0, 1, 2),
					variables: matchedVariables{},
				},
			},
			predicates: []Predicate{
				{
					Name: String(indexForFoo),
				},
				{
					Name: String(indexForBar),
				},
				{
					Name: String(indexForSpam),
				},
			},
			factSet: func() *FactSet {
				result := NewFactSet(
					*NewOrigin(0),
					Fact{Predicate{
						Name: String(indexForFoo),
					}},
				)
				result.Insert(
					*NewOrigin(1),
					Fact{Predicate{
						Name: String(indexForBar),
					}},
				)
				result.Insert(
					*NewOrigin(2),
					Fact{Predicate{
						Name: String(indexForSpam),
					}},
				)
				return result
			}(),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			sut := newCombineIt(tc.predicates, *tc.factSet)

			actual := make([]originAndVariables, 0, len(tc.expected))
			for origin, variables := range sut.matches() {
				actual = append(actual, originAndVariables{
					origin:    origin,
					variables: variables,
				})
			}

			require.Equal(t, tc.expected, actual)
		})
	}
}
