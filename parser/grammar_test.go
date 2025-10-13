// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"testing"
	"time"

	"github.com/alecthomas/participle/v2"
	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/stretchr/testify/require"
)

func TestGrammarPredicate(t *testing.T) {
	parser, err := participle.Build[Predicate](DefaultParserOptions...)
	require.NoError(t, err)

	testCases := []struct {
		Input    string
		Expected *Predicate
	}{
		{
			Input: `resource($var1)`,
			Expected: &Predicate{
				Name: sptr("resource"),
				IDs: []*Term{
					{Variable: varptr("var1")},
				},
			},
		},
		{
			Input: `resource({param1})`,
			Expected: &Predicate{
				Name: sptr("resource"),
				IDs: []*Term{
					{Parameter: paramptr("param1")},
				},
			},
		},
		{
			Input: `resource($0, "read")`,
			Expected: &Predicate{
				Name: sptr("resource"),
				IDs: []*Term{
					{Variable: varptr("0")},
					{String: sptr("read")},
				},
			},
		},
		{
			Input: `right("/a/file1.txt", "read")`,
			Expected: &Predicate{
				Name: sptr("right"),
				IDs: []*Term{
					{String: sptr("/a/file1.txt")},
					{String: sptr("read")},
				},
			},
		},
		{
			Input: `right("/a/file1.txt", "read")`,
			Expected: &Predicate{
				Name: sptr("right"),
				IDs: []*Term{
					{String: sptr("/a/file1.txt")},
					{String: sptr("read")},
				},
			},
		},
		{
			Input: `right("/a/file1.txt", $1)`,
			Expected: &Predicate{
				Name: sptr("right"),
				IDs: []*Term{
					{String: sptr("/a/file1.txt")},
					{Variable: varptr("1")},
				},
			},
		},
		{
			Input: `right($1, hex:41414141)`,
			Expected: &Predicate{
				Name: sptr("right"),
				IDs: []*Term{
					{Variable: varptr("1")},
					{Bytes: hexsptr("41414141")},
				},
			},
		},
		{
			Input: `right($1, [hex:41414141, "sym"])`,
			Expected: &Predicate{
				Name: sptr("right"),
				IDs: []*Term{
					{Variable: varptr("1")},
					{Set: []*Term{{Bytes: hexsptr("41414141")}, {String: sptr("sym")}}},
				},
			},
		},
		{
			Input: `right($1, true, false)`,
			Expected: &Predicate{
				Name: sptr("right"),
				IDs: []*Term{
					{Variable: varptr("1")},
					{Bool: boolptr(true)},
					{Bool: boolptr(false)},
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Input, func(t *testing.T) {
			parsed, err := parser.ParseString("test", testCase.Input)
			require.NoError(t, err)
			require.Equal(t, testCase.Expected, parsed)
		})
	}
}

func TestExprTerm(t *testing.T) {
	parser, err := participle.Build[ExprTerm](DefaultParserOptions...)
	require.NoError(t, err)

	parsed, err := parser.ParseString("test", "$0")
	require.NoError(t, err)
	require.Equal(t, &ExprTerm{
		Term: &Term{
			Variable: varptr("0"),
		},
	}, parsed)
}

func TestGrammarExpression(t *testing.T) {
	parser, err := participle.Build[Expression](DefaultParserOptions...)
	require.NoError(t, err)

	t1, _ := time.Parse(time.RFC3339, "2006-01-02T15:04:05Z")
	t2, _ := time.Parse(time.RFC3339, "2006-01-02T15:04:05+07:00")

	testCases := []struct {
		Input    string
		Params   ParametersMap
		Expected *biscuit.Expression
	}{
		{
			Input: `$0 == 1`,
			Expected: &biscuit.Expression{
				biscuit.Value{Term: biscuit.Variable("0")},
				biscuit.Value{Term: biscuit.Integer(1)},
				biscuit.BinaryEqual,
			},
		},
		{
			Input: `$1 > 2`,
			Expected: &biscuit.Expression{
				biscuit.Value{Term: biscuit.Variable("1")},
				biscuit.Value{Term: biscuit.Integer(2)},
				biscuit.BinaryGreaterThan,
			},
		},
		{
			Input: `$0 >= 1`,
			Expected: &biscuit.Expression{
				biscuit.Value{Term: biscuit.Variable("0")},
				biscuit.Value{Term: biscuit.Integer(1)},
				biscuit.BinaryGreaterOrEqual,
			},
		},
		{
			Input: `$0 < 1`,
			Expected: &biscuit.Expression{
				biscuit.Value{Term: biscuit.Variable("0")},
				biscuit.Value{Term: biscuit.Integer(1)},
				biscuit.BinaryLessThan,
			},
		},
		{
			Input: `$0 <= 1`,
			Expected: &biscuit.Expression{
				biscuit.Value{Term: biscuit.Variable("0")},
				biscuit.Value{Term: biscuit.Integer(1)},
				biscuit.BinaryLessOrEqual,
			},
		},
		{
			Input: `!$0`,
			Expected: &biscuit.Expression{
				biscuit.Value{Term: biscuit.Variable("0")},
				biscuit.UnaryNegate,
			},
		},
		{
			Input: `[1, 2, 3].contains($0)`,
			Expected: &biscuit.Expression{
				biscuit.Value{Term: biscuit.Set{biscuit.Integer(1), biscuit.Integer(2), biscuit.Integer(3)}},
				biscuit.Value{Term: biscuit.Variable("0")},
				biscuit.BinaryContains,
			},
		},
		{
			Input: `![4,5,6].contains($0)`,
			Expected: &biscuit.Expression{
				biscuit.Value{Term: biscuit.Set{biscuit.Integer(4), biscuit.Integer(5), biscuit.Integer(6)}},
				biscuit.Value{Term: biscuit.Variable("0")},
				biscuit.BinaryContains,
				biscuit.UnaryNegate,
			},
		},
		{
			Input: `$0 == "abc"`,
			Expected: &biscuit.Expression{
				biscuit.Value{Term: biscuit.Variable("0")},
				biscuit.Value{Term: biscuit.String("abc")},
				biscuit.BinaryEqual,
			},
		},
		{
			Input: `$0.starts_with("abc")`,
			Expected: &biscuit.Expression{
				biscuit.Value{Term: biscuit.Variable("0")},
				biscuit.Value{Term: biscuit.String("abc")},
				biscuit.BinaryPrefix,
			},
		},
		{
			Input: `$0.ends_with("abc")`,
			Expected: &biscuit.Expression{
				biscuit.Value{Term: biscuit.Variable("0")},
				biscuit.Value{Term: biscuit.String("abc")},
				biscuit.BinarySuffix,
			},
		},
		{
			Input: `$0.matches("^abc[a-z]+$") `,
			Expected: &biscuit.Expression{
				biscuit.Value{Term: biscuit.Variable("0")},
				biscuit.Value{Term: biscuit.String("^abc[a-z]+$")},
				biscuit.BinaryRegex,
			},
		},
		{
			Input: `["abc", "def"].contains($0)`,
			Expected: &biscuit.Expression{
				biscuit.Value{Term: biscuit.Set{biscuit.String("abc"), biscuit.String("def")}},
				biscuit.Value{Term: biscuit.Variable("0")},
				biscuit.BinaryContains,
			},
		},
		{
			Input: `!["abc", "def"].contains($0)`,
			Expected: &biscuit.Expression{
				biscuit.Value{Term: biscuit.Set{biscuit.String("abc"), biscuit.String("def")}},
				biscuit.Value{Term: biscuit.Variable("0")},
				biscuit.BinaryContains,
				biscuit.UnaryNegate,
			},
		},
		{
			Input: `$0 <= 2006-01-02T15:04:05Z`,
			Expected: &biscuit.Expression{
				biscuit.Value{Term: biscuit.Variable("0")},
				biscuit.Value{Term: biscuit.Date(t1)},
				biscuit.BinaryLessOrEqual,
			},
		},
		{
			Input: `$0 >= 2006-01-02T15:04:05+07:00`,
			Expected: &biscuit.Expression{
				biscuit.Value{Term: biscuit.Variable("0")},
				biscuit.Value{Term: biscuit.Date(t2)},
				biscuit.BinaryGreaterOrEqual,
			},
		},
		{
			Input: `[hex:41, hex:42, hex:43].contains($0)`,
			Expected: &biscuit.Expression{
				biscuit.Value{Term: biscuit.Set{biscuit.Bytes([]byte("A")),
					biscuit.Bytes([]byte("B")), biscuit.Bytes([]byte("C"))}},
				biscuit.Value{Term: biscuit.Variable("0")},
				biscuit.BinaryContains,
			},
		},
		{
			Input: `![hex:41, hex:42, hex:43].contains($0)`,
			Expected: &biscuit.Expression{
				biscuit.Value{Term: biscuit.Set{biscuit.Bytes([]byte("A")),
					biscuit.Bytes([]byte("B")), biscuit.Bytes([]byte("C"))}},
				biscuit.Value{Term: biscuit.Variable("0")},
				biscuit.BinaryContains,
				biscuit.UnaryNegate,
			},
		},
		{
			Input: `[hex:41].union([hex:42]).intersection([hex:41]).length() == $0`,
			Expected: &biscuit.Expression{
				biscuit.Value{Term: biscuit.Set{biscuit.Bytes([]byte("A"))}},
				biscuit.Value{Term: biscuit.Set{biscuit.Bytes([]byte("B"))}},
				biscuit.BinaryUnion,
				biscuit.Value{Term: biscuit.Set{biscuit.Bytes([]byte("A"))}},
				biscuit.BinaryIntersection,
				biscuit.UnaryLength,
				biscuit.Value{Term: biscuit.Variable("0")},
				biscuit.BinaryEqual,
			},
		},
		{
			Input: `hex:12ab == hex:ab`,
			Expected: &biscuit.Expression{
				biscuit.Value{Term: biscuit.Bytes([]byte{0x12, 0xab})},
				biscuit.Value{Term: biscuit.Bytes([]byte{0xab})},
				biscuit.BinaryEqual,
			},
		},
		{
			Input: `{param1} + {param2} * {param3} == {param4} || {param5}`,
			Params: map[string]biscuit.Term{
				"param1": biscuit.Integer(1),
				"param2": biscuit.Integer(2),
				"param3": biscuit.Integer(3),
				"param4": biscuit.Integer(7),
				"param5": biscuit.Bool(false),
			},
			Expected: &biscuit.Expression{
				biscuit.Value{Term: biscuit.Integer(1)},
				biscuit.Value{Term: biscuit.Integer(2)},
				biscuit.Value{Term: biscuit.Integer(3)},
				biscuit.BinaryMul,
				biscuit.BinaryAdd,
				biscuit.Value{Term: biscuit.Integer(7)},
				biscuit.BinaryEqual,
				biscuit.Value{Term: biscuit.Bool(false)},
				biscuit.BinaryOr,
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Input, func(t *testing.T) {
			parsed, err := parser.ParseString("test", testCase.Input)
			require.NoError(t, err, testCase.Input)

			var expr biscuit.Expression
			(*parsed).ToExpr(&expr, testCase.Params)
			require.Equal(t, testCase.Expected, &expr, testCase.Input)
		})
	}

}

func TestGrammarCheck(t *testing.T) {
	parser, err := participle.Build[Check](DefaultParserOptions...)
	require.NoError(t, err)

	testCases := []struct {
		Input    string
		Expected *Check
	}{
		{
			Input: `check if parent("a", "b"), parent("b", "c")`,
			Expected: &Check{
				Queries: []*CheckQuery{
					{
						Body: []*RuleElement{
							{
								Predicate: &Predicate{

									Name: sptr("parent"),
									IDs: []*Term{
										{String: sptr("a")},
										{String: sptr("b")},
									},
								},
							},
							{
								Predicate: &Predicate{

									Name: sptr("parent"),
									IDs: []*Term{
										{String: sptr("b")},
										{String: sptr("c")},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			Input: `check if parent("a", "b"), parent("b", "c")`,
			Expected: &Check{
				Queries: []*CheckQuery{
					{
						Body: []*RuleElement{
							{
								Predicate: &Predicate{
									Name: sptr("parent"),
									IDs: []*Term{
										{String: sptr("a")},
										{String: sptr("b")},
									},
								},
							},
							{
								Predicate: &Predicate{
									Name: sptr("parent"),
									IDs: []*Term{
										{String: sptr("b")},
										{String: sptr("c")},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			Input: `check if parent("a", "b"), parent("b", "c") or parent("a", "b"), parent("b", "c"), $0 > 42, $1.starts_with("test")`,
			Expected: &Check{
				Queries: []*CheckQuery{
					{
						Body: []*RuleElement{
							{
								Predicate: &Predicate{
									Name: sptr("parent"),
									IDs: []*Term{
										{String: sptr("a")},
										{String: sptr("b")},
									},
								},
							},
							{
								Predicate: &Predicate{
									Name: sptr("parent"),
									IDs: []*Term{
										{String: sptr("b")},
										{String: sptr("c")},
									},
								},
							},
						},
					},
					{
						Body: []*RuleElement{
							{
								Predicate: &Predicate{
									Name: sptr("parent"),
									IDs: []*Term{
										{String: sptr("a")},
										{String: sptr("b")},
									},
								},
							},
							{
								Predicate: &Predicate{
									Name: sptr("parent"),
									IDs: []*Term{
										{String: sptr("b")},
										{String: sptr("c")},
									},
								},
							},
							{
								Expression: &Expression{
									Left: &Expr1{
										Left: &Expr2{
											Left: &Expr3{
												Left: &Expr4{
													Left: &Expr5{
														Expr6: &Expr6{
															Left: &ExprTerm{
																Term: &Term{
																	Variable: varptr("0"),
																},
															},
														},
													},
												},
											},
											Right: &OpExpr3{
												Operator: OpGreaterThan,
												Expr3: &Expr3{
													Left: &Expr4{
														Left: &Expr5{
															Expr6: &Expr6{
																Left: &ExprTerm{
																	Term: &Term{
																		Integer: i64ptr(42),
																	},
																},
															},
														},
													},
												},
											},
										},
									},
								},
							},
							{
								Expression: &Expression{
									Left: &Expr1{
										Left: &Expr2{
											Left: &Expr3{
												Left: &Expr4{
													Left: &Expr5{
														Expr6: &Expr6{
															Left: &ExprTerm{
																Term: &Term{
																	Variable: varptr("1"),
																},
															},
															Right: []*OpExpr7{
																{
																	Operator: OpPrefix,
																	Expression: &Expression{
																		Left: &Expr1{
																			Left: &Expr2{
																				Left: &Expr3{
																					Left: &Expr4{
																						Left: &Expr5{
																							Expr6: &Expr6{
																								Left: &ExprTerm{
																									Term: &Term{
																										String: sptr("test"),
																									},
																								},
																							},
																						},
																					},
																				},
																			},
																		},
																	},
																},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				}},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Input, func(t *testing.T) {
			parsed, err := parser.ParseString("test", testCase.Input)
			require.NoError(t, err)
			require.Equal(t, testCase.Expected, parsed)
		})
	}
}

func TestGrammarBlock(t *testing.T) {
	parser, err := participle.Build[Block](DefaultParserOptions...)
	require.NoError(t, err)

	testCases := []struct {
		Input    string
		Expected *Block
	}{
		{
			Input: `// some comment
    fact(true);
    head($var) <- body($var);
	check if fact(true);`,
			Expected: &Block{
				Comments: []*Comment{commentptr("some comment")},
				Body: []*BlockElement{
					{
						Predicate: &Predicate{
							Name: sptr("fact"),
							IDs: []*Term{
								{Bool: boolptr(true)},
							},
						},
					},
					{
						Predicate: &Predicate{
							Name: sptr("head"),
							IDs: []*Term{
								{Variable: varptr("var")},
							},
						},
						RuleBody: []*RuleElement{
							{
								Predicate: &Predicate{
									Name: sptr("body"),
									IDs: []*Term{
										{Variable: varptr("var")},
									},
								},
							},
						},
					},
					{
						Check: &Check{
							Queries: []*CheckQuery{
								{
									Body: []*RuleElement{
										{
											Predicate: &Predicate{
												Name: sptr("fact"),
												IDs: []*Term{
													{Bool: boolptr(true)},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Input, func(t *testing.T) {
			parsed, err := parser.ParseString("test", testCase.Input)
			require.NoError(t, err)
			require.Equal(t, testCase.Expected, parsed)
		})
	}
}

func TestGrammarAuthorizer(t *testing.T) {
	parser, err := participle.Build[Authorizer](DefaultParserOptions...)
	require.NoError(t, err)

	testCases := []struct {
		Input    string
		Expected *Authorizer
	}{
		{
			Input: `// some comment
    fact(true);
    head($var) <- body($var);
	check if fact(true);
    allow if fact(true);`,
			Expected: &Authorizer{
				Comments: []*Comment{commentptr("some comment")},
				Body: []*AuthorizerElement{
					{
						BlockElement: &BlockElement{
							Predicate: &Predicate{
								Name: sptr("fact"),
								IDs: []*Term{
									{Bool: boolptr(true)},
								},
							},
						},
					},
					{
						BlockElement: &BlockElement{
							Predicate: &Predicate{
								Name: sptr("head"),
								IDs: []*Term{
									{Variable: varptr("var")},
								},
							},
							RuleBody: []*RuleElement{
								{
									Predicate: &Predicate{
										Name: sptr("body"),
										IDs: []*Term{
											{Variable: varptr("var")},
										},
									},
								},
							},
						},
					},
					{
						BlockElement: &BlockElement{
							Check: &Check{
								Queries: []*CheckQuery{
									{
										Body: []*RuleElement{
											{
												Predicate: &Predicate{
													Name: sptr("fact"),
													IDs: []*Term{
														{Bool: boolptr(true)},
													},
												},
											},
										},
									},
								},
							},
						},
					},
					{
						Policy: &Policy{
							Allow: &Allow{
								Queries: []*CheckQuery{
									{
										Body: []*RuleElement{
											{
												Predicate: &Predicate{
													Name: sptr("fact"),
													IDs: []*Term{
														{Bool: boolptr(true)},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Input, func(t *testing.T) {
			parsed, err := parser.ParseString("test", testCase.Input)
			require.NoError(t, err)
			require.Equal(t, testCase.Expected, parsed)
		})
	}
}

func varptr(s string) *Variable {
	v := Variable(s)
	return &v
}

func paramptr(s string) *Parameter {
	p := Parameter(s)
	return &p
}

func sptr(s string) *string {
	return &s
}

func i64ptr(i int64) *int64 {
	return &i
}

func hexsptr(s string) *HexString {
	h := HexString(s)
	return &h
}

func commentptr(s string) *Comment {
	c := Comment(s)
	return &c
}

func boolptr(b bool) *Bool {
	v := Bool(b)
	return &v
}
