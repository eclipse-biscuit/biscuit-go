// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"fmt"
	"testing"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2"
	"github.com/stretchr/testify/require"
)

type testCase struct {
	Input         string
	Expected      interface{}
	ExpectFailure bool
	ExpectErr     error
}

func getFactTestCases() []testCase {
	return []testCase{
		{
			Input: `right("/a/file1.txt", "read", ["read", "/a/file2.txt"])`,
			Expected: biscuit.Fact{
				Predicate: biscuit.Predicate{
					Name: "right",
					IDs: []biscuit.Term{
						biscuit.String("/a/file1.txt"),
						biscuit.String("read"),
						biscuit.Set{
							biscuit.String("read"),
							biscuit.String("/a/file2.txt"),
						},
					},
				},
			},
		},
		{
			Input:         `right("/a/file1.txt", $0)`,
			ExpectFailure: true,
			ExpectErr:     ErrVariableInFact,
		},
		{
			Input:         `right("/a/file1.txt"`,
			ExpectFailure: true,
		},
		{
			Input:         `right(/a/file1.txt")`,
			ExpectFailure: true,
		},
		{
			Input:         `right("/a/file1.txt", [$0])`,
			ExpectFailure: true,
		},
	}
}

func getRuleTestCases() []testCase {
	t1, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	t2, _ := time.Parse(time.RFC3339, time.Now().Add(2*time.Second).Format(time.RFC3339))

	return []testCase{
		{
			Input: `grandparent("a", "c") <- parent("a", "b"), parent("b", "c"), $0 > 42, $1.starts_with("abc")`,
			Expected: biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "grandparent",
					IDs: []biscuit.Term{
						biscuit.String("a"),
						biscuit.String("c"),
					},
				},
				Body: []biscuit.Predicate{
					{
						Name: "parent",
						IDs: []biscuit.Term{
							biscuit.String("a"),
							biscuit.String("b"),
						},
					},
					{
						Name: "parent",
						IDs: []biscuit.Term{
							biscuit.String("b"),
							biscuit.String("c"),
						},
					},
				},
				Expressions: []biscuit.Expression{
					{
						biscuit.Value{Term: biscuit.Variable("0")},
						biscuit.Value{Term: biscuit.Integer(42)},
						biscuit.BinaryGreaterThan,
					},
					{
						biscuit.Value{Term: biscuit.Variable("1")},
						biscuit.Value{Term: biscuit.String("abc")},
						biscuit.BinaryPrefix,
					},
				},
			},
		},
		{
			Input: `grandparent("a", "c") <- parent("a", "b"), parent("b", "c")`,
			Expected: biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "grandparent",
					IDs: []biscuit.Term{
						biscuit.String("a"),
						biscuit.String("c"),
					},
				},
				Body: []biscuit.Predicate{
					{
						Name: "parent",
						IDs: []biscuit.Term{
							biscuit.String("a"),
							biscuit.String("b"),
						},
					},
					{
						Name: "parent",
						IDs: []biscuit.Term{
							biscuit.String("b"),
							biscuit.String("c"),
						},
					},
				},
				Expressions: []biscuit.Expression{},
			},
		},
		{
			Input: fmt.Sprintf(`rule1("a") <- body1("b"), $0 > %s, $0 < %s`, t1.Format(time.RFC3339), t2.Format(time.RFC3339)),

			Expected: biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "rule1",
					IDs:  []biscuit.Term{biscuit.String("a")},
				},
				Body: []biscuit.Predicate{{
					Name: "body1",
					IDs:  []biscuit.Term{biscuit.String("b")},
				}},
				Expressions: []biscuit.Expression{
					{
						biscuit.Value{Term: biscuit.Variable("0")},
						biscuit.Value{Term: biscuit.Date(t1)},
						biscuit.BinaryGreaterThan,
					},
					{
						biscuit.Value{Term: biscuit.Variable("0")},
						biscuit.Value{Term: biscuit.Date(t2)},
						biscuit.BinaryLessThan,
					},
				},
			},
		},
		{
			Input:         fmt.Sprintf(`rule1("a") <- body1("b"), $0 > %s`, t1.Format(time.RFC1123)),
			ExpectFailure: true,
		},
		{
			Input: `rule1("a") <- body1("b"), $0 > 0, $1 < 1, $2 >= 2, $3 <= 3, $4 == 4, [1, 2, 3].contains($5), ![4,5,6].contains($6)`,
			Expected: biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "rule1",
					IDs:  []biscuit.Term{biscuit.String("a")},
				},
				Body: []biscuit.Predicate{{
					Name: "body1",
					IDs:  []biscuit.Term{biscuit.String("b")},
				}},
				Expressions: []biscuit.Expression{
					{
						biscuit.Value{Term: biscuit.Variable("0")},
						biscuit.Value{Term: biscuit.Integer(0)},
						biscuit.BinaryGreaterThan,
					},
					{
						biscuit.Value{Term: biscuit.Variable("1")},
						biscuit.Value{Term: biscuit.Integer(1)},
						biscuit.BinaryLessThan,
					},
					{
						biscuit.Value{Term: biscuit.Variable("2")},
						biscuit.Value{Term: biscuit.Integer(2)},
						biscuit.BinaryGreaterOrEqual,
					},
					{
						biscuit.Value{Term: biscuit.Variable("3")},
						biscuit.Value{Term: biscuit.Integer(3)},
						biscuit.BinaryLessOrEqual,
					},
					{
						biscuit.Value{Term: biscuit.Variable("4")},
						biscuit.Value{Term: biscuit.Integer(4)},
						biscuit.BinaryEqual,
					},
					{
						biscuit.Value{Term: biscuit.Set{biscuit.Integer(1), biscuit.Integer(2), biscuit.Integer(3)}},
						biscuit.Value{Term: biscuit.Variable("5")},
						biscuit.BinaryContains,
					},
					{
						biscuit.Value{Term: biscuit.Set{biscuit.Integer(4), biscuit.Integer(5), biscuit.Integer(6)}},
						biscuit.Value{Term: biscuit.Variable("6")},
						biscuit.BinaryContains,
						biscuit.UnaryNegate,
					},
				},
			},
		},
		{
			Input: `rule1("a") <- body1("b"), $0 == "abc", $1.starts_with("def"), $2.ends_with("ghi"), $3.matches("file[0-9]+.txt"), ["a","b"].contains($4), !["c", "d"].contains($5)`,
			Expected: biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "rule1",
					IDs:  []biscuit.Term{biscuit.String("a")},
				},
				Body: []biscuit.Predicate{{
					Name: "body1",
					IDs:  []biscuit.Term{biscuit.String("b")},
				}},
				Expressions: []biscuit.Expression{
					{
						biscuit.Value{Term: biscuit.Variable("0")},
						biscuit.Value{Term: biscuit.String("abc")},
						biscuit.BinaryEqual,
					},
					{
						biscuit.Value{Term: biscuit.Variable("1")},
						biscuit.Value{Term: biscuit.String("def")},
						biscuit.BinaryPrefix,
					},
					{
						biscuit.Value{Term: biscuit.Variable("2")},
						biscuit.Value{Term: biscuit.String("ghi")},
						biscuit.BinarySuffix,
					},
					{
						biscuit.Value{Term: biscuit.Variable("3")},
						biscuit.Value{Term: biscuit.String("file[0-9]+.txt")},
						biscuit.BinaryRegex,
					},
					{
						biscuit.Value{Term: biscuit.Set{biscuit.String("a"), biscuit.String("b")}},
						biscuit.Value{Term: biscuit.Variable("4")},
						biscuit.BinaryContains,
					},
					{
						biscuit.Value{Term: biscuit.Set{biscuit.String("c"), biscuit.String("d")}},
						biscuit.Value{Term: biscuit.Variable("5")},
						biscuit.BinaryContains,
						biscuit.UnaryNegate,
					},
				},
			},
		},
		{
			Input: `rule1("a") <- body1("b"), ["a", "b"].contains($0), !["c", "d"].contains($1)`,
			Expected: biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "rule1",
					IDs:  []biscuit.Term{biscuit.String("a")},
				},
				Body: []biscuit.Predicate{{
					Name: "body1",
					IDs:  []biscuit.Term{biscuit.String("b")},
				}},
				Expressions: []biscuit.Expression{
					{
						biscuit.Value{Term: biscuit.Set{biscuit.String("a"), biscuit.String("b")}},
						biscuit.Value{Term: biscuit.Variable("0")},
						biscuit.BinaryContains,
					},
					{
						biscuit.Value{Term: biscuit.Set{biscuit.String("c"), biscuit.String("d")}},
						biscuit.Value{Term: biscuit.Variable("1")},
						biscuit.BinaryContains,
						biscuit.UnaryNegate,
					},
				},
			},
		},
		{
			Input: `rule1("a") <- body1(hex:41414141)`,
			Expected: biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "rule1",
					IDs:  []biscuit.Term{biscuit.String("a")},
				},
				Body: []biscuit.Predicate{{
					Name: "body1",
					IDs:  []biscuit.Term{biscuit.Bytes([]byte{0x41, 0x41, 0x41, 0x41})},
				}},
				Expressions: []biscuit.Expression{},
			},
		},
		{
			Input: `rule1("a") <- body1(hex:41414141), $0 == hex:41414141`,
			Expected: biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "rule1",
					IDs:  []biscuit.Term{biscuit.String("a")},
				},
				Body: []biscuit.Predicate{{
					Name: "body1",
					IDs:  []biscuit.Term{biscuit.Bytes([]byte{0x41, 0x41, 0x41, 0x41})},
				}},
				Expressions: []biscuit.Expression{
					{
						biscuit.Value{Term: biscuit.Variable("0")},
						biscuit.Value{Term: biscuit.Bytes([]byte{0x41, 0x41, 0x41, 0x41})},
						biscuit.BinaryEqual,
					},
				},
			},
		},
		{
			Input: `rule1("a") <- body1($0, $1), ["abc", "def"].contains($0), ! [41, 42].contains($1)`,
			Expected: biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "rule1",
					IDs:  []biscuit.Term{biscuit.String("a")},
				},
				Body: []biscuit.Predicate{{
					Name: "body1",
					IDs:  []biscuit.Term{biscuit.Variable("0"), biscuit.Variable("1")},
				}},
				Expressions: []biscuit.Expression{
					{
						biscuit.Value{Term: biscuit.Set{biscuit.String("abc"), biscuit.String("def")}},
						biscuit.Value{Term: biscuit.Variable("0")},
						biscuit.BinaryContains,
					},
					{
						biscuit.Value{Term: biscuit.Set{biscuit.Integer(41), biscuit.Integer(42)}},
						biscuit.Value{Term: biscuit.Variable("1")},
						biscuit.BinaryContains,
						biscuit.UnaryNegate,
					},
				},
			},
		},

		{
			Input: `empty() <- body1($0, $1)`,
			Expected: biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "empty",
					IDs:  []biscuit.Term{},
				},
				Body: []biscuit.Predicate{{
					Name: "body1",
					IDs:  []biscuit.Term{biscuit.Variable("0"), biscuit.Variable("1")},
				}},
				Expressions: []biscuit.Expression{},
			},
		},
		{
			Input:         `grandparent(#a, #c) <-- parent(#a, #b), parent(#b, #c)`,
			ExpectFailure: true,
		},
		{
			Input:         `<- parent(#a, #b), parent(#b, #c)`,
			ExpectFailure: true,
		},
		{
			Input:         `rule1(#a) <- body1($0, $1), $0 in [$1, "foo"]`,
			ExpectFailure: true,
		},
		{
			// fails because precedence is not handled
			Input: `rule1("a") <- true || false && true`,

			Expected: biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "rule1",
					IDs:  []biscuit.Term{biscuit.String("a")},
				},
				Body: []biscuit.Predicate{},
				Expressions: []biscuit.Expression{
					{
						biscuit.Value{Term: biscuit.Bool(true)},
						biscuit.Value{Term: biscuit.Bool(false)},
						biscuit.Value{Term: biscuit.Bool(true)},
						biscuit.BinaryAnd,
						biscuit.BinaryOr,
					},
				},
			},
		},
		{
			Input: `rule1("a") <- 1 + 2 * 3 + 4 / 5`,

			Expected: biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "rule1",
					IDs:  []biscuit.Term{biscuit.String("a")},
				},
				Body: []biscuit.Predicate{},
				Expressions: []biscuit.Expression{
					{
						biscuit.Value{Term: biscuit.Integer(1)},
						biscuit.Value{Term: biscuit.Integer(2)},
						biscuit.Value{Term: biscuit.Integer(3)},
						biscuit.BinaryMul,
						biscuit.BinaryAdd,
						biscuit.Value{Term: biscuit.Integer(4)},
						biscuit.Value{Term: biscuit.Integer(5)},
						biscuit.BinaryDiv,
						biscuit.BinaryAdd,
					},
				},
			},
		},
		{
			Input: `rule1("a") <- 1 + 2 * (3 + 4)`,

			Expected: biscuit.Rule{
				Head: biscuit.Predicate{
					Name: "rule1",
					IDs:  []biscuit.Term{biscuit.String("a")},
				},
				Body: []biscuit.Predicate{},
				Expressions: []biscuit.Expression{
					{
						biscuit.Value{Term: biscuit.Integer(1)},
						biscuit.Value{Term: biscuit.Integer(2)},
						biscuit.Value{Term: biscuit.Integer(3)},
						biscuit.Value{Term: biscuit.Integer(4)},
						biscuit.BinaryAdd,
						biscuit.UnaryParens,
						biscuit.BinaryMul,
						biscuit.BinaryAdd,
					},
				},
			},
		},
	}
}

func getCheckTestCases() []testCase {
	return []testCase{
		{
			Input: `check if parent("a", "b"), parent("b", "c"), [1,2,3].contains($0) or right("read", "/a/file1.txt")`,
			Expected: biscuit.Check{
				Queries: []biscuit.Rule{
					{
						Head: biscuit.Predicate{
							Name: "query",
							IDs:  []biscuit.Term{},
						},
						Body: []biscuit.Predicate{
							{
								Name: "parent",
								IDs: []biscuit.Term{
									biscuit.String("a"),
									biscuit.String("b"),
								},
							},
							{
								Name: "parent",
								IDs: []biscuit.Term{
									biscuit.String("b"),
									biscuit.String("c"),
								},
							},
						},
						Expressions: []biscuit.Expression{
							{
								biscuit.Value{Term: biscuit.Set{biscuit.Integer(1), biscuit.Integer(2), biscuit.Integer(3)}},
								biscuit.Value{Term: biscuit.Variable("0")},
								biscuit.BinaryContains,
							},
						},
					},
					{
						Head: biscuit.Predicate{
							Name: "query",
							IDs:  []biscuit.Term{},
						},
						Body: []biscuit.Predicate{
							{
								Name: "right",
								IDs: []biscuit.Term{
									biscuit.String("read"),
									biscuit.String("/a/file1.txt"),
								},
							},
						},
						Expressions: []biscuit.Expression{},
					},
				},
			},
		},
		{
			Input:         `[ caveat1($0) <- parent(#a, #b), parent(#b, #c) @ $0 in [1,2,3]`,
			ExpectFailure: true,
		},
	}
}

func TestParserFact(t *testing.T) {
	p := New()
	for _, testCase := range getFactTestCases() {
		t.Run(testCase.Input, func(t *testing.T) {
			fact, err := p.Fact(testCase.Input, nil)
			if testCase.ExpectFailure {
				if testCase.ExpectErr != nil {
					require.Equal(t, testCase.ExpectErr, err)
				} else {
					require.Error(t, err)
				}
			} else {
				require.NoError(t, err)
				require.Equal(t, testCase.Expected, fact)
			}
		})
	}
}

func TestParseRule(t *testing.T) {
	p := New()
	for _, testCase := range getRuleTestCases() {
		t.Run(testCase.Input, func(t *testing.T) {
			rule, err := p.Rule(testCase.Input, nil)
			if testCase.ExpectFailure {
				if testCase.ExpectErr != nil {
					require.Equal(t, testCase.ExpectErr, err)
				} else {
					require.Error(t, err)
				}
			} else {
				require.NoError(t, err)
				require.Equal(t, testCase.Expected, rule)
			}
		})
	}
}

func TestParserCheck(t *testing.T) {
	p := New()
	for _, testCase := range getCheckTestCases() {
		t.Run(testCase.Input, func(t *testing.T) {
			caveat, err := p.Check(testCase.Input, nil)
			if testCase.ExpectFailure {
				if testCase.ExpectErr != nil {
					require.Equal(t, testCase.ExpectErr, err)
				} else {
					require.Error(t, err)
				}
			} else {
				require.NoError(t, err)
				require.Equal(t, testCase.Expected, caveat)
			}
		})
	}
}

func TestMustParserFact(t *testing.T) {
	p := New()
	for _, testCase := range getFactTestCases() {
		t.Run(testCase.Input, func(t *testing.T) {
			if testCase.ExpectFailure {
				defer func() {
					r := recover()
					require.NotNil(t, r)
				}()
			}

			fact := p.Must().Fact(testCase.Input, nil)
			require.Equal(t, testCase.Expected, fact)
		})
	}
}

// func TestMustParseRule(t *testing.T) {
// 	p := New()
// 	for _, testCase := range getRuleTestCases() {
// 		t.Run(testCase.Input, func(t *testing.T) {
// 			if testCase.ExpectFailure {
// 				defer func() {
// 					r := recover()
// 					require.NotNil(t, r)
// 				}()
// 			}
// 			rule := p.Must().Rule(testCase.Input)
// 			require.Equal(t, testCase.Expected, rule)
// 		})
// 	}
// }

// func TestMustParserCaveat(t *testing.T) {
// 	p := New()
// 	for _, testCase := range getCaveatTestCases() {
// 		t.Run(testCase.Input, func(t *testing.T) {
// 			if testCase.ExpectFailure {
// 				defer func() {
// 					r := recover()
// 					require.NotNil(t, r)
// 				}()
// 			}

// 			caveat := p.Must().Caveat(testCase.Input)
// 			require.Equal(t, testCase.Expected, caveat)
// 		})
// 	}
// }

func TestIssue84(t *testing.T) {
	rule, err := FromStringRule(`var($a) <- user($a), !($a == "abc")`)
	_ = rule
	require.NoError(t, err)
}
