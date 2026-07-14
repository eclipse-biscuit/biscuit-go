// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package datalog

import (
	"crypto/rand"
	"crypto/sha256"
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/eclipse-biscuit/biscuit-go/v2/internal/set"
)

// convertOrigin transforms a [[Origin]] into a []uint64 for easier comparison.
func convertOrigin(o Origin) []uint64 {
	var _ *set.HashSet[BlockID] = o.inner // Compiler check
	blockIDs := set.Sorted(o.inner.Iter())
	uints := make([]uint64, len(blockIDs))
	for i, blockID := range blockIDs {
		uints[i] = uint64(blockID)
	}
	return uints
}

// requireEqual requires equality using a diff comparison that transforms some types
// for convenience (both for comparison and for prettier printing).
func requireEqual(t *testing.T, expected, actual interface{}, msgAndArgs ...interface{}) {
	require.Empty(t,
		cmp.Diff(
			expected,
			actual,
			cmp.Transformer("Origin", convertOrigin),
			cmp.Transformer("Origins", func(origins []Origin) [][]uint64 {
				result := make([][]uint64, len(origins))
				for i, origin := range origins {
					result[i] = convertOrigin(origin)
				}
				return result
			}),
			cmp.Transformer("Set", func(s Set) []Term {
				return set.Sorted(s.HashSet.Iter())
			}),
		),
		msgAndArgs...,
	)
}

func hashVar(s string) Variable {
	h := sha256.Sum256([]byte(s))
	id := uint32(h[0]) +
		uint32(h[1])<<8 +
		uint32(h[2])<<16 +
		uint32(h[3])<<24
	return Variable(id)
}

func fact(pred Predicate) Fact {
	return Fact{Predicate: pred}
}

func TestFactSet(t *testing.T) {
	syms := &SymbolTable{}
	a := syms.Insert("A")
	b := syms.Insert("B")
	c := syms.Insert("C")
	parent := syms.Insert("parent")
	other := syms.Insert("parent")
	origin1 := *NewOrigin(0)

	fact1 := fact(Predicate{parent, []Term{a, b}})
	fact2 := fact(Predicate{parent, []Term{a, c}})

	otherFs := NewFactSet(origin1, fact(Predicate{other, []Term{}}))

	fs1 := NewFactSet(
		origin1,
		fact1,
		fact2,
	)

	require.Equal(t, uint64(2), fs1.Count())
	require.True(t, fs1.Equal(fs1))
	require.False(t, fs1.Equal(otherFs))
	requireEqual(t, []Origin{origin1}, slices.Collect(fs1.Origins()))
	require.Equal(t, []Fact{fact1, fact2}, set.Sorted(fs1.Facts(origin1)))
	require.Equal(t, []Fact{fact1, fact2}, set.Sorted(fs1.AllFacts()))

	{
		// Test `Iter()`.
		actual := make(map[string][]Fact)
		for k, v := range fs1.Iter() {
			actual[k.EncodeToString()] = set.Sorted(v.Iter())
		}
		expected := map[string][]Fact{
			"0": []Fact{fact1, fact2},
		}
		require.Equal(t, expected, actual)
	}

	origin2 := *NewOrigin(1)
	fact3 := fact(Predicate{parent, []Term{a}})

	fs1.Insert(origin2, fact3)

	require.Equal(t, uint64(3), fs1.Count())
	require.Len(t, slices.Collect(fs1.Origins()), 2)
	require.Contains(t, slices.Collect(fs1.Origins()), origin1)
	require.Contains(t, slices.Collect(fs1.Origins()), origin2)
	require.Equal(t, []Fact{fact1, fact2}, set.Sorted(fs1.Facts(origin1)))
	require.Equal(t, []Fact{fact3}, set.Sorted(fs1.Facts(origin2)))
	require.Contains(t, slices.Collect(fs1.AllFacts()), fact1)
	require.Contains(t, slices.Collect(fs1.AllFacts()), fact2)
	require.Contains(t, slices.Collect(fs1.AllFacts()), fact3)

	{
		// Test `Iter()`.
		actual := make(map[string][]Fact)
		for k, v := range fs1.Iter() {
			actual[k.EncodeToString()] = set.Sorted(v.Iter())
		}
		expected := map[string][]Fact{
			"0": {fact1, fact2},
			"1": {fact3},
		}
		require.Equal(t, expected, actual)
	}

	fs2 := make(FactSet)
	fs2.InsertMulti(origin1, []Fact{fact1, fact2})
	fs2.InsertMulti(origin2, []Fact{fact3})

	require.Equal(t, uint64(3), fs2.Count())
	require.True(t, fs2.Equal(&fs2))
	require.True(t, fs1.Equal(&fs2))
	require.True(t, fs2.Equal(fs1))
	require.False(t, fs2.Equal(otherFs))

	origin3 := *NewOrigin(0, 1)
	fact4 := fact(Predicate{parent, []Term{b, c}})

	require.False(t, fs1.InsertNew(origin1, fact1))
	require.True(t, fs1.InsertNew(origin3, fact4))
	require.Equal(t, uint64(4), fs1.Count())
}

func TestOrigin(t *testing.T) {
	t.Run("construction", func(t *testing.T) {
		testCases := map[string]struct {
			expected func(t *testing.T) *Origin
			actual   func(t *testing.T) *Origin
		}{
			"from encoded string with one ID": {
				expected: func(t *testing.T) *Origin {
					return NewOrigin(0)
				},
				actual: func(t *testing.T) *Origin {
					result, err := NewOriginFromString("0")
					require.NoError(t, err)
					return result
				},
			},
			"from encoded string with two IDs": {
				expected: func(t *testing.T) *Origin {
					return NewOrigin(0, 1)
				},
				actual: func(t *testing.T) *Origin {
					result, err := NewOriginFromString("0,1")
					require.NoError(t, err)
					return result
				},
			},
			"with IDs inserted as ints": {
				expected: func(t *testing.T) *Origin {
					return NewOrigin(0, 1, 2, 3)
				},
				actual: func(t *testing.T) *Origin {
					return NewOrigin(0, 1, 2, 3)
				},
			},
			"with IDs inserted as BlockID slice": {
				expected: func(t *testing.T) *Origin {
					return NewOrigin(0, 1, 2, 3)
				},
				actual: func(t *testing.T) *Origin {
					return NewOrigin(0, 1, 2, 3)
				},
			},
			"with other Origin inserted": {
				expected: func(t *testing.T) *Origin {
					return NewOrigin(0, 1, 2, 3)
				},
				actual: func(t *testing.T) *Origin {
					return NewOrigin(0, 1, 2, 3)
				},
			},
			"with IDs inserted using 'With`": {
				expected: func(t *testing.T) *Origin {
					return NewOrigin(0, 1, 2, 3)
				},
				actual: func(t *testing.T) *Origin {
					return NewOrigin(0, 1, 2, 3)
				},
			},
		}

		for name, tc := range testCases {
			t.Run(name, func(t *testing.T) {
				requireEqual(t, tc.expected(t), tc.actual(t))
			})
		}
	})

	t.Run("decoding an empty origin is an error", func(t *testing.T) {
		_, err := NewOriginFromString("")
		require.ErrorContains(t, err, "empty")
	})

	t.Run("IsSuperSet", func(t *testing.T) {
		origin := NewOrigin(0, 1, 2, 3)

		require.True(t, origin.IsSuperSet(NewOrigin(0)))
		require.True(t, origin.IsSuperSet(NewOrigin(1, 2)))
		require.False(t, origin.IsSuperSet(NewOrigin(0, 6)))
		require.False(t, origin.IsSuperSet(NewOrigin(7, 8, 9)))
	})

	t.Run("encoding format", func(t *testing.T) {
		// Single ID
		o1 := NewOrigin(0)
		require.Equal(t, "0", o1.EncodeToString())

		// Multiple IDs (should be sorted)
		o2 := NewOrigin(3, 1, 2)
		require.Equal(t, "1,2,3", o2.EncodeToString())

		// Base 36 encoding for large numbers
		o3 := NewOrigin(AuthorizerBlockID)
		encoded := o3.EncodeToString()
		decoded, err := NewOriginFromString(encoded)
		require.NoError(t, err)
		requireEqual(t, o3, decoded)
	})

	t.Run("deduplication", func(t *testing.T) {
		o := NewOrigin(1, 2, 1, 3, 2) // Duplicates
		requireEqual(t, NewOrigin(1, 2, 3), o)
	})

	t.Run("sorting", func(t *testing.T) {
		// Origins containing AuthorizerBlockID should sort before others
		o1 := NewOrigin(AuthorizerBlockID)    // [Auth]
		o2 := NewOrigin(AuthorizerBlockID, 1) // [Auth, 1]
		o3 := NewOrigin(0)                    // [0]
		o4 := NewOrigin(0, 1)                 // [0, 1]

		// Expected sort order: [Auth] < [Auth, 1] < [0] < [0, 1]
		require.Less(t, o1.Compare(*o2), 0, "[Auth] should come before [Auth, 1]")
		require.Less(t, o1.Compare(*o3), 0, "[Auth] should come before [0]")
		require.Less(t, o2.Compare(*o3), 0, "[Auth, 1] should come before [0]")
		require.Less(t, o3.Compare(*o4), 0, "[0] should come before [0, 1]")
	})
}

func TestFamily(t *testing.T) {
	w := NewWorld()
	syms := &SymbolTable{}
	dbg := SymbolDebugger{syms, nil}
	a := syms.Insert("A")
	b := syms.Insert("B")
	c := syms.Insert("C")
	d := syms.Insert("D")
	e := syms.Insert("e")
	parent := syms.Insert("parent")
	grandparent := syms.Insert("grandparent")
	origin := *NewOrigin(0)

	w.AddFact(origin, fact(Predicate{parent, []Term{a, b}}))
	w.AddFact(origin, fact(Predicate{parent, []Term{b, c}}))
	w.AddFact(origin, fact(Predicate{parent, []Term{c, d}}))

	r1 := Rule{
		Head: Predicate{grandparent, []Term{hashVar("grandparent"), hashVar("grandchild")}},
		Body: []Predicate{
			{parent, []Term{hashVar("grandparent"), hashVar("parent")}},
			{parent, []Term{hashVar("parent"), hashVar("grandchild")}},
		},
	}

	trustedOrigin := *NewTrustedOrigin().With(0)

	t.Logf("querying r1: %s", dbg.Rule(r1))
	queryRuleResult, err := w.QueryRule(r1, trustedOrigin, syms)
	require.NoError(t, err)
	t.Logf("r1 query: %s", dbg.FactSet(queryRuleResult))
	t.Logf("current Facts: %s", dbg.FactSet(w.Facts))

	r2 := Rule{
		Head: Predicate{grandparent, []Term{hashVar("grandparent"), hashVar("grandchild")}},
		Body: []Predicate{
			{parent, []Term{hashVar("grandparent"), hashVar("parent")}},
			{parent, []Term{hashVar("parent"), hashVar("grandchild")}},
		},
	}

	t.Logf("adding r2: %s", dbg.Rule(r2))
	w.AddRule(trustedOrigin, 0, r2)
	if err := w.Run(syms); err != nil {
		t.Error(err)
	}

	w.AddFact(origin, fact(Predicate{parent, []Term{c, e}}))
	if err := w.Run(syms); err != nil {
		t.Error(err)
	}

	res := w.Query(Predicate{grandparent, []Term{hashVar("grandparent"), hashVar("grandchild")}})
	t.Logf("grandparents after inserting parent(C, E): %s", dbg.FactSet(*res))
	expected := NewFactSet(
		origin,
		fact(Predicate{grandparent, []Term{a, c}}),
		fact(Predicate{grandparent, []Term{b, d}}),
		fact(Predicate{grandparent, []Term{b, e}}),
	)
	if !res.Equal(expected) {
		t.Errorf("unexpected result:\nhave %s\n want %s", dbg.FactSet(*res), dbg.FactSet(*expected))
	}
}

func TestNumbers(t *testing.T) {
	w := NewWorld()
	syms := &SymbolTable{}
	dbg := SymbolDebugger{syms, nil}

	abc := syms.Insert("abc")
	def := syms.Insert("def")
	ghi := syms.Insert("ghi")
	jkl := syms.Insert("jkl")
	mno := syms.Insert("mno")
	aaa := syms.Insert("AAA")
	bbb := syms.Insert("BBB")
	ccc := syms.Insert("CCC")
	t1 := syms.Insert("t1")
	t2 := syms.Insert("t2")
	join := syms.Insert("join")

	origin := *NewOrigin(0)

	w.AddFact(origin, fact(Predicate{t1, []Term{Integer(0), abc}}))
	w.AddFact(origin, fact(Predicate{t1, []Term{Integer(1), def}}))
	w.AddFact(origin, fact(Predicate{t1, []Term{Integer(2), ghi}}))
	w.AddFact(origin, fact(Predicate{t1, []Term{Integer(3), jkl}}))
	w.AddFact(origin, fact(Predicate{t1, []Term{Integer(4), mno}}))

	w.AddFact(origin, fact(Predicate{t2, []Term{Integer(0), aaa, Integer(0)}}))
	w.AddFact(origin, fact(Predicate{t2, []Term{Integer(1), bbb, Integer(0)}}))
	w.AddFact(origin, fact(Predicate{t2, []Term{Integer(2), ccc, Integer(1)}}))

	trustedOrigin := *NewTrustedOrigin().With(0)

	res, err := w.QueryRule(
		Rule{
			Head: Predicate{join, []Term{hashVar("left"), hashVar("right")}},
			Body: []Predicate{
				{t1, []Term{hashVar("id"), hashVar("left")}},
				{t2, []Term{hashVar("t2_id"), hashVar("right"), hashVar("id")}},
			},
		},
		trustedOrigin,
		syms,
	)
	require.NoError(t, err)
	expected := NewFactSet(
		*NewOrigin(0, AuthorizerBlockID),
		fact(Predicate{join, []Term{abc, aaa}}),
		fact(Predicate{join, []Term{abc, bbb}}),
		fact(Predicate{join, []Term{def, ccc}}),
	)
	if !expected.Equal(&res) {
		t.Errorf("query failed:\n have: %s\n want: %s", dbg.FactSet(res), dbg.FactSet(*expected))
	}

	res, err = w.QueryRule(
		Rule{
			Head: Predicate{join, []Term{hashVar("left"), hashVar("right")}},
			Body: []Predicate{
				{t1, []Term{Variable(1234), hashVar("left")}},
				{t2, []Term{hashVar("t2_id"), hashVar("right"), Variable(1234)}},
			},
			Expressions: []Expression{{
				Value{Variable(1234)},
				Value{Integer(1)},
				BinaryOp{LessThan{}},
			}},
		},
		trustedOrigin,
		syms,
	)
	require.NoError(t, err)
	expected = NewFactSet(
		*NewOrigin(0, AuthorizerBlockID),
		fact(Predicate{join, []Term{abc, aaa}}),
		fact(Predicate{join, []Term{abc, bbb}}),
	)
	if !expected.Equal(&res) {
		t.Errorf("constraint query failed:\n have: %s\n want: %s", dbg.FactSet(res), dbg.FactSet(*expected))
	}
}

func TestString(t *testing.T) {
	w := NewWorld()
	syms := &SymbolTable{}
	dbg := SymbolDebugger{syms, nil}

	app0 := syms.Insert("app_0")
	app1 := syms.Insert("app_1")
	app2 := syms.Insert("app_2")
	route := syms.Insert("route")
	suff := syms.Insert("route suffix")

	origin := *NewOrigin(0)

	w.AddFact(origin, fact(Predicate{route, []Term{Integer(0), app0, syms.Insert("example.com")}}))
	w.AddFact(origin, fact(Predicate{route, []Term{Integer(1), app1, syms.Insert("test.com")}}))
	w.AddFact(origin, fact(Predicate{route, []Term{Integer(2), app2, syms.Insert("test.fr")}}))
	w.AddFact(origin, fact(Predicate{route, []Term{Integer(3), app0, syms.Insert("www.example.com")}}))
	w.AddFact(origin, fact(Predicate{route, []Term{Integer(4), app1, syms.Insert("mx.example.com")}}))

	trustedOrigin := *NewTrustedOrigin().With(0)

	testSuffix := func(t *testing.T, suffix string, syms *SymbolTable) *FactSet {
		t.Helper()
		result, err := w.QueryRule(
			Rule{
				Head: Predicate{suff, []Term{hashVar("app_id"), Variable(1234)}},
				Body: []Predicate{{route, []Term{Variable(0), hashVar("app_id"), Variable(1234)}}},
				Expressions: []Expression{{
					Value{Variable(1234)},
					Value{syms.Insert(suffix)},
					BinaryOp{Suffix{}},
				}},
			},
			trustedOrigin,
			syms,
		)
		require.NoError(t, err)
		return &result
	}

	res := testSuffix(t, ".fr", syms)
	expected := NewFactSet(
		*NewOrigin(0, AuthorizerBlockID),
		fact(Predicate{suff, []Term{app2, syms.Insert("test.fr")}}),
	)
	if !expected.Equal(res) {
		t.Errorf(".fr suffix query failed:\n have: %s\n want: %s", dbg.FactSet(*res), dbg.FactSet(*expected))
	}

	res = testSuffix(t, "example.com", syms)
	expected = NewFactSet(
		*NewOrigin(0, AuthorizerBlockID),
		fact(Predicate{suff, []Term{app0, syms.Insert("example.com")}}),
		fact(Predicate{suff, []Term{app0, syms.Insert("www.example.com")}}),
		fact(Predicate{suff, []Term{app1, syms.Insert("mx.example.com")}}),
	)
	if !expected.Equal(res) {
		t.Errorf("example.com suffix query failed:\n have: %s\n want: %s", dbg.FactSet(*res), dbg.FactSet(*expected))
	}
}

func TestDate(t *testing.T) {
	w := NewWorld()
	syms := &SymbolTable{}
	dbg := SymbolDebugger{syms, nil}

	t1 := time.Unix(1, 0)
	t2 := t1.Add(10 * time.Second)
	t3 := t2.Add(30 * time.Second)

	abc := syms.Insert("abc")
	def := syms.Insert("def")
	x := syms.Insert("x")
	before := syms.Insert("before")
	after := syms.Insert("after")

	origin := *NewOrigin(0)

	w.AddFact(origin, fact(Predicate{x, []Term{Date(t1.Unix()), abc}}))
	w.AddFact(origin, fact(Predicate{x, []Term{Date(t3.Unix()), def}}))

	trustedOrigin := *NewTrustedOrigin().With(0)

	res, err := w.QueryRule(
		Rule{
			Head: Predicate{before, []Term{Variable(1234), hashVar("val")}},
			Body: []Predicate{{x, []Term{Variable(1234), hashVar("val")}}},
			Expressions: []Expression{{
				Value{Variable(1234)},
				Value{Date(t2.Unix())},
				BinaryOp{LessOrEqual{}},
			}, {
				Value{Variable(1234)},
				Value{Date(0)},
				BinaryOp{GreaterOrEqual{}},
			}},
		},
		trustedOrigin,
		syms,
	)
	require.NoError(t, err)
	expected := NewFactSet(
		*NewOrigin(0, AuthorizerBlockID),
		fact(Predicate{before, []Term{Date(t1.Unix()), abc}}),
	)
	if !expected.Equal(&res) {
		t.Errorf("before query failed:\n have: %s\n want: %s", dbg.FactSet(res), dbg.FactSet(*expected))
	}

	res, err = w.QueryRule(
		Rule{
			Head: Predicate{after, []Term{Variable(1234), hashVar("val")}},
			Body: []Predicate{{x, []Term{Variable(1234), hashVar("val")}}},
			Expressions: []Expression{{
				Value{Variable(1234)},
				Value{Date(t2.Unix())},
				BinaryOp{GreaterOrEqual{}},
			}, {
				Value{Variable(1234)},
				Value{Date(0)},
				BinaryOp{GreaterOrEqual{}},
			}},
		},
		trustedOrigin,
		syms,
	)
	require.NoError(t, err)
	expected = NewFactSet(
		*NewOrigin(0, AuthorizerBlockID),
		fact(Predicate{after, []Term{Date(t3.Unix()), def}}),
	)
	if !expected.Equal(&res) {
		t.Errorf("before query failed:\n have: %s\n want: %s", dbg.FactSet(res), dbg.FactSet(*expected))
	}
}

func TestBytes(t *testing.T) {
	w := NewWorld()
	syms := &SymbolTable{}
	dbg := SymbolDebugger{syms, nil}

	k1 := make([]byte, 32)
	_, err := rand.Read(k1)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}

	k2 := make([]byte, 32)
	_, err = rand.Read(k2)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}

	k3 := make([]byte, 64)
	_, err = rand.Read(k3)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}

	usr1 := syms.Insert("usr1")
	usr2 := syms.Insert("usr2")
	usr3 := syms.Insert("usr3")

	key := syms.Insert("pkey")
	keyMatch := syms.Insert("pkey match")

	origin := *NewOrigin(0)

	w.AddFact(origin, fact(Predicate{key, []Term{usr1, Bytes(k1)}}))
	w.AddFact(origin, fact(Predicate{key, []Term{usr2, Bytes(k2)}}))
	w.AddFact(origin, fact(Predicate{key, []Term{usr3, Bytes(k3)}}))

	trustedOrigin := *NewTrustedOrigin().With(0)

	res, err := w.QueryRule(
		Rule{
			Head: Predicate{keyMatch, []Term{hashVar("usr"), Variable(1)}},
			Body: []Predicate{{key, []Term{hashVar("usr"), Variable(1)}}},
			Expressions: []Expression{{
				Value{Variable(1)},
				Value{Bytes(k1)},
				BinaryOp{Equal{}},
			}},
		},
		trustedOrigin,
		syms,
	)
	require.NoError(t, err)
	expected := NewFactSet(
		*NewOrigin(0, AuthorizerBlockID),
		fact(Predicate{keyMatch, []Term{usr1, Bytes(k1)}}),
	)
	if !expected.Equal(&res) {
		t.Errorf("key equal query failed:\n have: %s\n want: %s", dbg.FactSet(res), dbg.FactSet(*expected))
	}

	res, err = w.QueryRule(
		Rule{
			Head: Predicate{keyMatch, []Term{hashVar("usr"), Variable(1)}},
			Body: []Predicate{{key, []Term{hashVar("usr"), Variable(1)}}},
			Expressions: []Expression{{
				Value{NewSet(Bytes(k1), Bytes(k3))},
				Value{Variable(1)},
				BinaryOp{Contains{}},
			}},
		},
		trustedOrigin,
		syms,
	)
	require.NoError(t, err)
	expected = NewFactSet(
		*NewOrigin(0, AuthorizerBlockID),
		fact(Predicate{keyMatch, []Term{usr1, Bytes(k1)}}),
		fact(Predicate{keyMatch, []Term{usr3, Bytes(k3)}}),
	)
	if !expected.Equal(&res) {
		t.Errorf("key in query failed:\n have: %s\n want: %s", dbg.FactSet(res), dbg.FactSet(*expected))
	}

	res, err = w.QueryRule(
		Rule{
			Head: Predicate{keyMatch, []Term{hashVar("usr"), Variable(1)}},
			Body: []Predicate{{key, []Term{hashVar("usr"), Variable(1)}}},
			Expressions: []Expression{{
				Value{NewSet(Bytes(k1))},
				Value{Variable(1)},
				BinaryOp{Contains{}},
				UnaryOp{Negate{}},
			}},
		},
		trustedOrigin,
		syms,
	)
	require.NoError(t, err)
	expected = NewFactSet(
		*NewOrigin(0, AuthorizerBlockID),
		fact(Predicate{keyMatch, []Term{usr2, Bytes(k2)}}),
		fact(Predicate{keyMatch, []Term{usr3, Bytes(k3)}}),
	)
	if !expected.Equal(&res) {
		t.Errorf("key not in query failed:\n have: %s\n want: %s", dbg.FactSet(res), dbg.FactSet(*expected))
	}
}

func TestResource(t *testing.T) {
	w := NewWorld()
	syms := &SymbolTable{}
	dbg := SymbolDebugger{syms, nil}

	authority := syms.Insert("authority")
	ambient := syms.Insert("ambient")
	resource := syms.Insert("resource")
	operation := syms.Insert("operation")
	right := syms.Insert("right")
	file1 := syms.Insert("file1")
	file2 := syms.Insert("file2")
	read := syms.Insert("read")
	write := syms.Insert("write")

	origin := *NewOrigin(0)

	w.AddFact(origin, fact(Predicate{resource, []Term{ambient, file2}}))
	w.AddFact(origin, fact(Predicate{operation, []Term{ambient, write}}))
	w.AddFact(origin, fact(Predicate{right, []Term{authority, file1, read}}))
	w.AddFact(origin, fact(Predicate{right, []Term{authority, file2, read}}))
	w.AddFact(origin, fact(Predicate{right, []Term{authority, file1, write}}))

	trustedOrigin := *NewTrustedOrigin().With(0)

	check1 := syms.Insert("check1")
	res, err := w.QueryRule(
		Rule{
			Head: Predicate{check1, []Term{file1}},
			Body: []Predicate{{resource, []Term{ambient, file1}}},
		},
		trustedOrigin,
		syms,
	)
	require.NoError(t, err)
	if res.Count() > 0 {
		t.Errorf("unexpected Facts: %s", dbg.FactSet(res))
	}

	check2 := syms.Insert("check2")
	var0 := Variable(0)
	r2 := Rule{
		Head: Predicate{check2, []Term{var0}},
		Body: []Predicate{
			{resource, []Term{ambient, var0}},
			{operation, []Term{ambient, read}},
			{right, []Term{authority, var0, read}},
		},
	}
	t.Logf("r2 = %s", dbg.Rule(r2))
	res, err = w.QueryRule(r2, trustedOrigin, syms)
	require.NoError(t, err)
	if res.Count() > 0 {
		t.Errorf("unexpected Facts: %s", dbg.FactSet(res))
	}
}

func TestSymbolTable(t *testing.T) {
	s1 := new(SymbolTable)
	s2 := &SymbolTable{"a", "b", "c"}
	s3 := &SymbolTable{"d", "e", "f"}

	require.True(t, s1.IsDisjoint(s2))
	s1.Extend(s2)
	require.False(t, s1.IsDisjoint(s2))
	require.Equal(t, s2, s1)
	s1.Extend(s3)
	require.Equal(t, SymbolTable(append(*s2, *s3...)), *s1)

	require.Equal(t, len(*s2)+len(*s3), s1.Len())

	newSyms := s1.SplitOff(len(*s2))
	require.Equal(t, s3, newSyms)
	require.Equal(t, s2, s1)
}

func TestSymbolTableInsertAndSym(t *testing.T) {
	s := new(SymbolTable)
	require.Equal(t, String(1024), s.Insert("a"))
	require.Equal(t, String(1025), s.Insert("b"))
	require.Equal(t, String(1026), s.Insert("c"))

	require.Equal(t, &SymbolTable{"a", "b", "c"}, s)

	require.Equal(t, String(1024), s.Insert("a"))
	require.Equal(t, String(1027), s.Insert("d"))

	require.Equal(t, &SymbolTable{"a", "b", "c", "d"}, s)

	require.Equal(t, String(1024), s.Sym("a"))
	require.Equal(t, String(1025), s.Sym("b"))
	require.Equal(t, String(1026), s.Sym("c"))
	require.Equal(t, String(1027), s.Sym("d"))
	require.Equal(t, nil, s.Sym("e"))
}

func TestSymbolTableClone(t *testing.T) {
	s := new(SymbolTable)

	s.Insert("a")
	s.Insert("b")
	s.Insert("c")

	s2 := s.Clone()
	s2.Insert("a")
	s2.Insert("d")
	s2.Insert("e")

	require.Equal(t, &SymbolTable{"a", "b", "c"}, s)
	require.Equal(t, &SymbolTable{"a", "b", "c", "d", "e"}, s2)
}

func TestSetEqual(t *testing.T) {
	syms := &SymbolTable{}

	testCases := []struct {
		desc  string
		s1    Set
		s2    Set
		equal bool
	}{
		{
			desc:  "equal with same values in same order",
			s1:    NewSet(syms.Insert("a"), syms.Insert("b"), syms.Insert("c")),
			s2:    NewSet(syms.Insert("a"), syms.Insert("b"), syms.Insert("c")),
			equal: true,
		},
		{
			desc:  "equal with same values different order",
			s1:    NewSet(syms.Insert("a"), syms.Insert("b"), syms.Insert("c")),
			s2:    NewSet(syms.Insert("b"), syms.Insert("c"), syms.Insert("a")),
			equal: true,
		},
		{
			desc:  "not equal when length mismatch",
			s1:    NewSet(syms.Insert("a"), syms.Insert("b"), syms.Insert("c")),
			s2:    NewSet(syms.Insert("a"), syms.Insert("b")),
			equal: false,
		},
		{
			desc:  "not equal when length mismatch",
			s1:    NewSet(syms.Insert("a"), syms.Insert("b"), syms.Insert("c")),
			s2:    NewSet(syms.Insert("a"), syms.Insert("b"), syms.Insert("c"), syms.Insert("d")),
			equal: false,
		},
		{
			desc:  "not equal when same length but different values",
			s1:    NewSet(syms.Insert("a"), syms.Insert("b"), syms.Insert("c")),
			s2:    NewSet(syms.Insert("a"), syms.Insert("b"), syms.Insert("d")),
			equal: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.desc, func(t *testing.T) {
			if testCase.equal {
				requireEqual(t, testCase.s1, testCase.s2)
			} else {
				require.False(t, testCase.s1.Equal(testCase.s2))
			}
		})
	}
}

func TestWorldRunLimits(t *testing.T) {
	syms := &SymbolTable{}
	a := syms.Insert("A")
	b := syms.Insert("B")
	c := syms.Insert("C")
	d := syms.Insert("D")
	parent := syms.Insert("parent")
	grandparent := syms.Insert("grandparent")

	testCases := []struct {
		desc        string
		opts        []WorldOption
		expectedErr error
	}{
		{
			desc:        "valid defaults",
			expectedErr: nil,
		},
		{
			desc: "timeout",
			opts: []WorldOption{
				WithMaxDuration(0),
			},
			expectedErr: ErrWorldRunLimitTimeout,
		},
		{
			desc: "max iteration exceeded",
			opts: []WorldOption{
				WithMaxIterations(1),
			},
			expectedErr: ErrWorldRunLimitMaxIterations,
		},
		{
			desc: "max iteration ok",
			opts: []WorldOption{
				WithMaxIterations(2),
			},
			expectedErr: nil,
		},
		{
			desc: "max facts exceeded",
			opts: []WorldOption{
				WithMaxFacts(5),
			},
			expectedErr: ErrWorldRunLimitMaxFacts,
		},
		{
			desc: "max Facts ok",
			opts: []WorldOption{
				WithMaxFacts(6),
			},
			expectedErr: nil,
		},
	}

	for _, tc := range testCases {
		w := NewWorld(tc.opts...)

		origin := *NewOrigin(0)

		w.AddFact(origin, fact(Predicate{parent, []Term{a, b}}))
		w.AddFact(origin, fact(Predicate{parent, []Term{b, c}}))
		w.AddFact(origin, fact(Predicate{parent, []Term{c, d}}))

		r1 := Rule{
			Head: Predicate{grandparent, []Term{hashVar("grandparent"), hashVar("grandchild")}},
			Body: []Predicate{
				{parent, []Term{hashVar("grandparent"), hashVar("parent")}},
				{parent, []Term{hashVar("parent"), hashVar("grandchild")}},
			},
		}

		trustedOrigin := NewTrustedOrigin().With(0)

		w.AddRule(*trustedOrigin, 0, r1)
		require.Equal(t, tc.expectedErr, w.Run(syms))
	}
}
