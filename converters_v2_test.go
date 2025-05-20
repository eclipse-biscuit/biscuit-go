// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package biscuit

import (
	"math"
	"testing"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2/datalog"
	"github.com/biscuit-auth/biscuit-go/v2/pb"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestExpressionConvertV2(t *testing.T) {
	now := time.Now()
	syms := &datalog.SymbolTable{}

	testCases := []struct {
		Desc     string
		Input    datalog.Expression
		Expected *pb.ExpressionV2
	}{
		{
			Desc: "date comparison after",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Variable(1)},
				datalog.Value{ID: datalog.Date(now.Unix())},
				datalog.BinaryOp{BinaryOpFunc: datalog.GreaterOrEqual{}},
			},
			Expected: &pb.ExpressionV2{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Variable{Variable: 1}}}},
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Date{Date: uint64(now.Unix())}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_GreaterOrEqual.Enum()}}},
				},
			},
		},
		{
			Desc: "date comparison before",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Variable(2)},
				datalog.Value{ID: datalog.Date(123456789)},
				datalog.BinaryOp{BinaryOpFunc: datalog.LessOrEqual{}},
			},
			Expected: &pb.ExpressionV2{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Variable{Variable: 2}}}},
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Date{Date: uint64(123456789)}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_LessOrEqual.Enum()}}},
				},
			},
		},
		{
			Desc: "int comparison equal",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Variable(3)},
				datalog.Value{ID: datalog.Integer(42)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Equal{}},
			},
			Expected: &pb.ExpressionV2{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Variable{Variable: 3}}}},
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Integer{Integer: 42}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Equal.Enum()}}},
				},
			},
		},
		{
			Desc: "int comparison larger",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Variable(4)},
				datalog.Value{ID: datalog.Integer(-42)},
				datalog.BinaryOp{BinaryOpFunc: datalog.GreaterThan{}},
			},
			Expected: &pb.ExpressionV2{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Variable{Variable: 4}}}},
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Integer{Integer: -42}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_GreaterThan.Enum()}}},
				},
			},
		},
		{
			Desc: "int comparison larger or equal",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Variable(5)},
				datalog.Value{ID: datalog.Integer(43)},
				datalog.BinaryOp{BinaryOpFunc: datalog.GreaterOrEqual{}},
			},
			Expected: &pb.ExpressionV2{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Variable{Variable: 5}}}},
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Integer{Integer: 43}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_GreaterOrEqual.Enum()}}},
				},
			},
		},
		{
			Desc: "int comparison lower",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Variable(6)},
				datalog.Value{ID: datalog.Integer(0)},
				datalog.BinaryOp{BinaryOpFunc: datalog.LessThan{}},
			},
			Expected: &pb.ExpressionV2{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Variable{Variable: 6}}}},
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Integer{Integer: 0}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_LessThan.Enum()}}},
				},
			},
		},
		{
			Desc: "int comparison lower or equal",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Variable(7)},
				datalog.Value{ID: datalog.Integer(math.MaxInt64)},
				datalog.BinaryOp{BinaryOpFunc: datalog.LessOrEqual{}},
			},
			Expected: &pb.ExpressionV2{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Variable{Variable: 7}}}},
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Integer{Integer: math.MaxInt64}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_LessOrEqual.Enum()}}},
				},
			},
		},
		{
			Desc: "int comparison in",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Set{datalog.Integer(1), datalog.Integer(2), datalog.Integer(3)}},
				datalog.Value{ID: datalog.Variable(8)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Contains{}},
			},
			Expected: &pb.ExpressionV2{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Set{Set: &pb.TermSet{Set: []*pb.TermV2{
						{Content: &pb.TermV2_Integer{Integer: 1}},
						{Content: &pb.TermV2_Integer{Integer: 2}},
						{Content: &pb.TermV2_Integer{Integer: 3}},
					}}}}}},
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Variable{Variable: 8}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Contains.Enum()}}},
				},
			},
		},
		{
			Desc: "int comparison not in",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Set{datalog.Integer(1), datalog.Integer(2), datalog.Integer(3)}},
				datalog.Value{ID: datalog.Variable(9)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Contains{}},
				datalog.UnaryOp{UnaryOpFunc: datalog.Negate{}},
			},
			Expected: &pb.ExpressionV2{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Set{Set: &pb.TermSet{Set: []*pb.TermV2{
						{Content: &pb.TermV2_Integer{Integer: 1}},
						{Content: &pb.TermV2_Integer{Integer: 2}},
						{Content: &pb.TermV2_Integer{Integer: 3}},
					}}}}}},
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Variable{Variable: 9}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Contains.Enum()}}},
					{Content: &pb.Op_Unary{Unary: &pb.OpUnary{Kind: pb.OpUnary_Negate.Enum()}}},
				},
			},
		},

		{
			Desc: "string comparison equal",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Variable(10)},
				datalog.Value{ID: syms.Insert("abcd")},
				datalog.BinaryOp{BinaryOpFunc: datalog.Equal{}},
			},
			Expected: &pb.ExpressionV2{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Variable{Variable: 10}}}},
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_String_{String_: syms.Index("abcd")}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Equal.Enum()}}},
				},
			},
		},
		{
			Desc: "string comparison prefix",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Variable(11)},
				datalog.Value{ID: syms.Insert("abcd")},
				datalog.BinaryOp{BinaryOpFunc: datalog.Prefix{}},
			},
			Expected: &pb.ExpressionV2{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Variable{Variable: 11}}}},
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_String_{String_: syms.Index("abcd")}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Prefix.Enum()}}},
				},
			},
		},
		{
			Desc: "string comparison suffix",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Variable(12)},
				datalog.Value{ID: syms.Insert("abcd")},
				datalog.BinaryOp{BinaryOpFunc: datalog.Suffix{}},
			},
			Expected: &pb.ExpressionV2{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Variable{Variable: 12}}}},
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_String_{String_: syms.Index("abcd")}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Suffix.Enum()}}},
				},
			},
		},
		{
			Desc: "string comparison in",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Set{syms.Insert("a"), syms.Insert("b"), syms.Insert("c")}},
				datalog.Value{ID: datalog.Variable(13)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Contains{}},
			},
			Expected: &pb.ExpressionV2{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Set{Set: &pb.TermSet{Set: []*pb.TermV2{
						{Content: &pb.TermV2_String_{String_: syms.Index("a")}},
						{Content: &pb.TermV2_String_{String_: syms.Index("b")}},
						{Content: &pb.TermV2_String_{String_: syms.Index("c")}},
					}}}}}},
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Variable{Variable: 13}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Contains.Enum()}}},
				},
			},
		},
		{
			Desc: "string comparison not in",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Set{syms.Insert("a"), syms.Insert("b"), syms.Insert("c")}},
				datalog.Value{ID: datalog.Variable(14)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Contains{}},
				datalog.UnaryOp{UnaryOpFunc: datalog.Negate{}},
			},
			Expected: &pb.ExpressionV2{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Set{Set: &pb.TermSet{Set: []*pb.TermV2{
						{Content: &pb.TermV2_String_{String_: syms.Index("a")}},
						{Content: &pb.TermV2_String_{String_: syms.Index("b")}},
						{Content: &pb.TermV2_String_{String_: syms.Index("c")}},
					}}}}}},
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Variable{Variable: 14}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Contains.Enum()}}},
					{Content: &pb.Op_Unary{Unary: &pb.OpUnary{Kind: pb.OpUnary_Negate.Enum()}}},
				},
			},
		},
		{
			Desc: "string regexp",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Variable(15)},
				datalog.Value{ID: syms.Insert("abcd")},
				datalog.BinaryOp{BinaryOpFunc: datalog.Regex{}},
			},
			Expected: &pb.ExpressionV2{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Variable{Variable: 15}}}},
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_String_{String_: syms.Index("abcd")}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Regex.Enum()}}},
				},
			},
		},
		{
			Desc: "bytes equal",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Variable(16)},
				datalog.Value{ID: datalog.Bytes("abcd")},
				datalog.BinaryOp{BinaryOpFunc: datalog.Equal{}},
			},
			Expected: &pb.ExpressionV2{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Variable{Variable: 16}}}},
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Bytes{Bytes: []byte("abcd")}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Equal.Enum()}}},
				},
			},
		},
		{
			Desc: "bytes in",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Set{datalog.Bytes("a"), datalog.Bytes("b"), datalog.Bytes("c")}},
				datalog.Value{ID: datalog.Variable(17)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Contains{}},
			},
			Expected: &pb.ExpressionV2{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Set{Set: &pb.TermSet{Set: []*pb.TermV2{
						{Content: &pb.TermV2_Bytes{Bytes: []byte("a")}},
						{Content: &pb.TermV2_Bytes{Bytes: []byte("b")}},
						{Content: &pb.TermV2_Bytes{Bytes: []byte("c")}},
					}}}}}},
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Variable{Variable: 17}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Contains.Enum()}}},
				},
			},
		},
		{
			Desc: "bytes not in",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Set{datalog.Bytes("a"), datalog.Bytes("b"), datalog.Bytes("c")}},
				datalog.Value{ID: datalog.Variable(18)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Contains{}},
				datalog.UnaryOp{UnaryOpFunc: datalog.Negate{}},
			},
			Expected: &pb.ExpressionV2{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Set{Set: &pb.TermSet{Set: []*pb.TermV2{
						{Content: &pb.TermV2_Bytes{Bytes: []byte("a")}},
						{Content: &pb.TermV2_Bytes{Bytes: []byte("b")}},
						{Content: &pb.TermV2_Bytes{Bytes: []byte("c")}},
					}}}}}},
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Variable{Variable: 18}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Contains.Enum()}}},
					{Content: &pb.Op_Unary{Unary: &pb.OpUnary{Kind: pb.OpUnary_Negate.Enum()}}},
				},
			},
		},
		{
			Desc: "symbols in",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Set{datalog.String(1), datalog.String(2), datalog.String(3)}},
				datalog.Value{ID: datalog.Variable(19)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Contains{}},
			},
			Expected: &pb.ExpressionV2{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Set{Set: &pb.TermSet{Set: []*pb.TermV2{
						{Content: &pb.TermV2_String_{String_: 1}},
						{Content: &pb.TermV2_String_{String_: 2}},
						{Content: &pb.TermV2_String_{String_: 3}},
					}}}}}},
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Variable{Variable: 19}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Contains.Enum()}}},
				},
			},
		},
		{
			Desc: "symbols not in",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Set{datalog.String(1), datalog.String(2), datalog.String(3)}},
				datalog.Value{ID: datalog.Variable(20)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Contains{}},
				datalog.UnaryOp{UnaryOpFunc: datalog.Negate{}},
			},
			Expected: &pb.ExpressionV2{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Set{Set: &pb.TermSet{Set: []*pb.TermV2{
						{Content: &pb.TermV2_String_{String_: 1}},
						{Content: &pb.TermV2_String_{String_: 2}},
						{Content: &pb.TermV2_String_{String_: 3}},
					}}}}}},
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Variable{Variable: 20}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Contains.Enum()}}},
					{Content: &pb.Op_Unary{Unary: &pb.OpUnary{Kind: pb.OpUnary_Negate.Enum()}}},
				},
			},
		},
		{
			Desc: "add",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Variable(21)},
				datalog.Value{ID: datalog.Integer(42)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Add{}},
			},
			Expected: &pb.ExpressionV2{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Variable{Variable: 21}}}},
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Integer{Integer: 42}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Add.Enum()}}},
				},
			},
		},
		{
			Desc: "sub",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Variable(22)},
				datalog.Value{ID: datalog.Integer(42)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Sub{}},
			},
			Expected: &pb.ExpressionV2{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Variable{Variable: 22}}}},
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Integer{Integer: 42}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Sub.Enum()}}},
				},
			},
		},
		{
			Desc: "mul",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Variable(23)},
				datalog.Value{ID: datalog.Integer(42)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Mul{}},
			},
			Expected: &pb.ExpressionV2{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Variable{Variable: 23}}}},
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Integer{Integer: 42}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Mul.Enum()}}},
				},
			},
		},
		{
			Desc: "div",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Variable(24)},
				datalog.Value{ID: datalog.Integer(42)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Div{}},
			},
			Expected: &pb.ExpressionV2{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Variable{Variable: 24}}}},
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Integer{Integer: 42}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Div.Enum()}}},
				},
			},
		},
		{
			Desc: "and",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Variable(25)},
				datalog.Value{ID: datalog.Bool(true)},
				datalog.BinaryOp{BinaryOpFunc: datalog.And{}},
			},
			Expected: &pb.ExpressionV2{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Variable{Variable: 25}}}},
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Bool{Bool: true}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_And.Enum()}}},
				},
			},
		},
		{
			Desc: "or",
			Input: datalog.Expression{
				datalog.Value{ID: datalog.Variable(26)},
				datalog.Value{ID: datalog.Bool(true)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Or{}},
			},
			Expected: &pb.ExpressionV2{
				Ops: []*pb.Op{
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Variable{Variable: 26}}}},
					{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Bool{Bool: true}}}},
					{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Or.Enum()}}},
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			out, err := tokenExpressionToProtoExpressionV2(testCase.Input)
			require.NoError(t, err)

			require.Equal(t, testCase.Expected, out)

			dlout, err := protoExpressionToTokenExpressionV2(out)
			require.NoError(t, err)
			require.Equal(t, testCase.Input, dlout)
		})
	}
}

func TestRuleConvertV2(t *testing.T) {
	now := time.Now()
	syms := &datalog.SymbolTable{}

	in := &datalog.Rule{
		Head: datalog.Predicate{
			Name:  datalog.String(42),
			Terms: []datalog.Term{datalog.Integer(1), syms.Insert("id_1")},
		},
		Body: []datalog.Predicate{
			{
				Name:  datalog.String(43),
				Terms: []datalog.Term{datalog.String(2), datalog.Date(now.Unix())},
			}, {
				Name:  datalog.String(44),
				Terms: []datalog.Term{datalog.Bytes([]byte("abcd"))},
			},
		},
		Expressions: []datalog.Expression{
			{
				datalog.Value{ID: datalog.Variable(9)},
				datalog.Value{ID: datalog.Integer(42)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Equal{}},
			},
			{
				datalog.Value{ID: datalog.Variable(99)},
				datalog.Value{ID: syms.Insert("abcd")},
				datalog.BinaryOp{BinaryOpFunc: datalog.Prefix{}},
			},
		},
	}

	name1 := uint64(42)
	name2 := uint64(43)
	name3 := uint64(44)
	expectedPbRule := &pb.RuleV2{
		Head: &pb.PredicateV2{Name: &name1, Terms: []*pb.TermV2{
			{Content: &pb.TermV2_Integer{Integer: 1}},
			{Content: &pb.TermV2_String_{String_: syms.Index("id_1")}},
		}},
		Body: []*pb.PredicateV2{
			{
				Name: &name2,
				Terms: []*pb.TermV2{
					{Content: &pb.TermV2_String_{String_: 2}},
					{Content: &pb.TermV2_Date{Date: uint64(now.Unix())}},
				},
			},
			{
				Name: &name3,
				Terms: []*pb.TermV2{
					{Content: &pb.TermV2_Bytes{Bytes: []byte("abcd")}},
				},
			},
		},
		Expressions: []*pb.ExpressionV2{
			{Ops: []*pb.Op{
				{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Variable{Variable: 9}}}},
				{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Integer{Integer: 42}}}},
				{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Equal.Enum()}}},
			}},
			{Ops: []*pb.Op{
				{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Variable{Variable: 99}}}},
				{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_String_{String_: syms.Index("abcd")}}}},
				{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Prefix.Enum()}}},
			}},
		},
	}

	pbRule, err := tokenRuleToProtoRuleV2(*in)
	require.NoError(t, err)
	require.Equal(t, expectedPbRule, pbRule)
	out, err := protoRuleToTokenRuleV2(pbRule)
	require.NoError(t, err)
	require.Equal(t, in, out)
}

func TestFactConvertV2(t *testing.T) {
	now := time.Now()
	syms := &datalog.SymbolTable{}

	in := &datalog.Fact{Predicate: datalog.Predicate{
		Name: datalog.String(42),
		Terms: []datalog.Term{
			datalog.String(1),
			datalog.Integer(2),
			datalog.Variable(3),
			datalog.Bytes([]byte("bytes")),
			syms.Insert("abcd"),
			datalog.Date(now.Unix()),
			datalog.Bool(true),
			datalog.Set{
				syms.Insert("abc"),
				syms.Insert("def"),
			},
		},
	}}

	name1 := uint64(42)
	expectedPbFact := &pb.FactV2{Predicate: &pb.PredicateV2{
		Name: &name1,
		Terms: []*pb.TermV2{
			{Content: &pb.TermV2_String_{String_: 1}},
			{Content: &pb.TermV2_Integer{Integer: 2}},
			{Content: &pb.TermV2_Variable{Variable: 3}},
			{Content: &pb.TermV2_Bytes{Bytes: []byte("bytes")}},
			{Content: &pb.TermV2_String_{String_: syms.Index("abcd")}},
			{Content: &pb.TermV2_Date{Date: uint64(now.Unix())}},
			{Content: &pb.TermV2_Bool{Bool: true}},
			{Content: &pb.TermV2_Set{Set: &pb.TermSet{Set: []*pb.TermV2{
				{Content: &pb.TermV2_String_{String_: syms.Index("abc")}},
				{Content: &pb.TermV2_String_{String_: syms.Index("def")}},
			}}}},
		},
	}}

	pbFact, err := tokenFactToProtoFactV2(*in)
	require.NoError(t, err)
	require.Equal(t, expectedPbFact, pbFact)

	out, err := protoFactToTokenFactV2(pbFact)
	require.NoError(t, err)
	require.Equal(t, in, out)
}

func TestConvertInvalTermsets(t *testing.T) {
	syms := &datalog.SymbolTable{}

	tokenTestCases := []struct {
		desc string
		in   datalog.Set
	}{
		{
			desc: "empty set",
			in:   datalog.Set{},
		},
		{
			desc: "mixed element types",
			in: datalog.Set{
				syms.Insert("abc"),
				datalog.Integer(1),
			},
		},
		{
			desc: "set with variables",
			in: datalog.Set{
				datalog.Variable(0),
				datalog.Variable(1),
			},
		},
		{
			desc: "set with sub sets",
			in: datalog.Set{
				datalog.Set{
					syms.Insert("abc"),
					syms.Insert("def"),
				},
			},
		},
	}

	protoTestCases := []struct {
		desc string
		in   *pb.TermV2
	}{
		{
			desc: "empty set",
			in: &pb.TermV2{Content: &pb.TermV2_Set{Set: &pb.TermSet{
				Set: []*pb.TermV2{},
			}}},
		},
		{
			desc: "mixed element types",
			in: &pb.TermV2{Content: &pb.TermV2_Set{Set: &pb.TermSet{
				Set: []*pb.TermV2{
					{Content: &pb.TermV2_String_{String_: syms.Index("abc")}},
					{Content: &pb.TermV2_Integer{Integer: 0}},
				},
			}}},
		},
		{
			desc: "set with variables",
			in: &pb.TermV2{Content: &pb.TermV2_Set{Set: &pb.TermSet{
				Set: []*pb.TermV2{
					{Content: &pb.TermV2_Variable{Variable: 1}},
				},
			}}},
		},
		{
			desc: "set with sub sets",
			in: &pb.TermV2{Content: &pb.TermV2_Set{Set: &pb.TermSet{
				Set: []*pb.TermV2{
					{Content: &pb.TermV2_Set{Set: &pb.TermSet{Set: []*pb.TermV2{
						{Content: &pb.TermV2_String_{String_: syms.Index("abc")}},
					}}}},
				},
			}}},
		},
	}

	for _, tc := range tokenTestCases {
		t.Run(tc.desc, func(t *testing.T) {
			_, err := tokenIDToProtoIDV2(tc.in)
			require.Error(t, err)
		})
	}

	for _, tc := range protoTestCases {
		t.Run(tc.desc, func(t *testing.T) {
			_, err := protoIDToTokenIDV2(tc.in)
			require.Error(t, err)
		})
	}
}

func TestBlockConvertV2(t *testing.T) {
	syms := &datalog.SymbolTable{}

	predicate := datalog.Predicate{
		Name:  datalog.String(12),
		Terms: []datalog.Term{syms.Insert("abcd")},
	}

	name1 := uint64(12)
	pbPredicate := &pb.PredicateV2{
		Name:  &name1,
		Terms: []*pb.TermV2{{Content: &pb.TermV2_String_{String_: syms.Index("abcd")}}},
	}

	rule := &datalog.Rule{
		Head: predicate,
		Body: []datalog.Predicate{predicate},
		Expressions: []datalog.Expression{
			{
				datalog.Value{ID: datalog.Variable(datalog.OFFSET + 13)},
				datalog.Value{ID: datalog.Integer(1234)},
				datalog.BinaryOp{BinaryOpFunc: datalog.Equal{}},
			},
		},
	}

	pbRule := &pb.RuleV2{
		Head: pbPredicate,
		Body: []*pb.PredicateV2{pbPredicate},
		Expressions: []*pb.ExpressionV2{
			{Ops: []*pb.Op{
				{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Variable{Variable: uint32(datalog.OFFSET + 13)}}}},
				{Content: &pb.Op_Value{Value: &pb.TermV2{Content: &pb.TermV2_Integer{Integer: 1234}}}},
				{Content: &pb.Op_Binary{Binary: &pb.OpBinary{Kind: pb.OpBinary_Equal.Enum()}}},
			}},
		},
	}

	in := &Block{
		symbols: &datalog.SymbolTable{"a", "b", "c", "d"},
		facts:   &datalog.FactSet{datalog.Fact{Predicate: predicate}},
		rules:   []datalog.Rule{*rule},
		checks:  []datalog.Check{{Queries: []datalog.Rule{*rule}}},
		context: "context",
		version: 3,
	}

	ctx := "context"
	version := uint32(3)
	expectedPbBlock := &pb.Block{
		Symbols: []string{"a", "b", "c", "d"},
		FactsV2: []*pb.FactV2{
			{Predicate: pbPredicate},
		},
		RulesV2:  []*pb.RuleV2{pbRule},
		ChecksV2: []*pb.CheckV2{{Queries: []*pb.RuleV2{pbRule}}},
		Context:  &ctx,
		Version:  proto.Uint32(version),
	}

	pbBlock, err := tokenBlockToProtoBlock(in)
	require.NoError(t, err)
	require.Equal(t, expectedPbBlock, pbBlock)

	out, err := protoBlockToTokenBlock(pbBlock)
	require.NoError(t, err)
	require.Equal(t, in, out)

	version = uint32(MaxSchemaVersion + 1)
	pbBlock.Version = proto.Uint32(version)
	_, err = protoBlockToTokenBlock(pbBlock)
	require.Error(t, err)
}
