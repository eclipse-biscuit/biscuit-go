// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package biscuit

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/biscuit-auth/biscuit-go/v2/datalog"
	"github.com/biscuit-auth/biscuit-go/v2/pb"
)

func tokenFactToProtoFactV2(input datalog.Fact) (*pb.FactV2, error) {
	pred, err := tokenPredicateToProtoPredicateV2(input.Predicate)
	if err != nil {
		return nil, err
	}

	return &pb.FactV2{
		Predicate: pred,
	}, nil
}

func protoFactToTokenFactV2(input *pb.FactV2) (*datalog.Fact, error) {
	pred, err := protoPredicateToTokenPredicateV2(input.Predicate)
	if err != nil {
		return nil, err
	}
	return &datalog.Fact{
		Predicate: *pred,
	}, nil
}

func tokenPredicateToProtoPredicateV2(input datalog.Predicate) (*pb.PredicateV2, error) {
	pbTerms := make([]*pb.TermV2, len(input.Terms))
	var err error
	for i, id := range input.Terms {
		pbTerms[i], err = tokenIDToProtoIDV2(id)
		if err != nil {
			return nil, err
		}
	}

	nameSymbol := uint64(input.Name)
	return &pb.PredicateV2{
		Name:  &nameSymbol,
		Terms: pbTerms,
	}, nil
}

func protoPredicateToTokenPredicateV2(input *pb.PredicateV2) (*datalog.Predicate, error) {
	Terms := make([]datalog.Term, len(input.Terms))
	for i, id := range input.Terms {
		dlid, err := protoIDToTokenIDV2(id)
		if err != nil {
			return nil, err
		}

		Terms[i] = *dlid
	}

	nameSymbol := datalog.String(*input.Name)
	return &datalog.Predicate{
		Name:  nameSymbol,
		Terms: Terms,
	}, nil
}

func tokenIDToProtoIDV2(input datalog.Term) (*pb.TermV2, error) {
	var pbId *pb.TermV2
	switch input.Type() {
	case datalog.TermTypeString:
		pbId = &pb.TermV2{
			Content: &pb.TermV2_String_{String_: uint64(input.(datalog.String))},
		}
	case datalog.TermTypeDate:
		pbId = &pb.TermV2{
			Content: &pb.TermV2_Date{Date: uint64(input.(datalog.Date))},
		}
	case datalog.TermTypeInteger:
		pbId = &pb.TermV2{
			Content: &pb.TermV2_Integer{Integer: int64(input.(datalog.Integer))},
		}
	case datalog.TermTypeVariable:
		pbId = &pb.TermV2{
			Content: &pb.TermV2_Variable{Variable: uint32(input.(datalog.Variable))},
		}
	case datalog.TermTypeBytes:
		pbId = &pb.TermV2{
			Content: &pb.TermV2_Bytes{Bytes: input.(datalog.Bytes)},
		}
	case datalog.TermTypeBool:
		pbId = &pb.TermV2{
			Content: &pb.TermV2_Bool{Bool: bool(input.(datalog.Bool))},
		}
	case datalog.TermTypeSet:
		datalogSet := input.(datalog.Set)
		if len(datalogSet) == 0 {
			return nil, errors.New("biscuit: failed to convert token ID to proto ID: set cannot be empty")
		}

		expectedEltType := datalogSet[0].Type()
		switch expectedEltType {
		case datalog.TermTypeVariable:
			return nil, errors.New("biscuit: failed to convert token ID to proto ID: set cannot contains variable")
		case datalog.TermTypeSet:
			return nil, errors.New("biscuit: failed to convert token ID to proto ID: set cannot contains other sets")
		}

		protoSet := make([]*pb.TermV2, 0, len(datalogSet))
		for _, datalogElt := range datalogSet {
			if datalogElt.Type() != expectedEltType {
				return nil, fmt.Errorf(
					"biscuit: failed to convert token ID to proto ID: set elements must have the same type (got %x, want %x)",
					datalogElt.Type(),
					expectedEltType,
				)
			}

			protoElt, err := tokenIDToProtoIDV2(datalogElt)
			if err != nil {
				return nil, err
			}

			protoSet = append(protoSet, protoElt)
		}
		pbId = &pb.TermV2{
			Content: &pb.TermV2_Set{
				Set: &pb.TermSet{
					Set: protoSet,
				},
			},
		}
	default:
		return nil, fmt.Errorf("biscuit: failed to convert token ID to proto ID: unsupported id type: %v", input.Type())
	}
	return pbId, nil
}

func protoIDToTokenIDV2(input *pb.TermV2) (*datalog.Term, error) {
	var id datalog.Term
	switch input.Content.(type) {
	case *pb.TermV2_String_:
		id = datalog.String(input.GetString_())
	case *pb.TermV2_Date:
		id = datalog.Date(input.GetDate())
	case *pb.TermV2_Integer:
		id = datalog.Integer(input.GetInteger())
	case *pb.TermV2_Variable:
		id = datalog.Variable(input.GetVariable())
	case *pb.TermV2_Bytes:
		id = datalog.Bytes(input.GetBytes())
	case *pb.TermV2_Bool:
		id = datalog.Bool(input.GetBool())
	case *pb.TermV2_Set:
		elts := input.GetSet().Set
		if len(elts) == 0 {
			return nil, errors.New("biscuit: failed to convert proto ID to token ID: set cannot be empty")
		}

		expectedEltType := reflect.TypeOf(elts[0].GetContent())
		switch expectedEltType {
		case reflect.TypeOf(&pb.TermV2_Variable{}):
			return nil, errors.New("biscuit: failed to convert proto ID to token ID: set cannot contains variable")
		case reflect.TypeOf(&pb.TermV2_Set{}):
			return nil, errors.New("biscuit: failed to convert proto ID to token ID: set cannot contains other sets")
		}

		datalogSet := make(datalog.Set, 0, len(elts))
		for _, protoElt := range elts {
			if eltType := reflect.TypeOf(protoElt.GetContent()); eltType != expectedEltType {
				return nil, fmt.Errorf(
					"biscuit: failed to convert proto ID to token ID: set elements must have the same type (got %x, want %x)",
					eltType,
					expectedEltType,
				)
			}

			datalogElt, err := protoIDToTokenIDV2(protoElt)
			if err != nil {
				return nil, err
			}
			datalogSet = append(datalogSet, *datalogElt)
		}
		id = datalogSet
	default:
		return nil, fmt.Errorf("biscuit: failed to convert proto ID to token ID: unsupported id type: %T", input.Content)
	}

	return &id, nil
}

func tokenRuleToProtoRuleV2(input datalog.Rule) (*pb.RuleV2, error) {
	pbBody := make([]*pb.PredicateV2, len(input.Body))
	for i, p := range input.Body {
		pred, err := tokenPredicateToProtoPredicateV2(p)
		if err != nil {
			return nil, err
		}
		pbBody[i] = pred
	}

	pbExpressions := make([]*pb.ExpressionV2, len(input.Expressions))
	for i, e := range input.Expressions {
		expr, err := tokenExpressionToProtoExpressionV2(e)
		if err != nil {
			return nil, err
		}
		pbExpressions[i] = expr
	}

	pbHead, err := tokenPredicateToProtoPredicateV2(input.Head)
	if err != nil {
		return nil, err
	}

	return &pb.RuleV2{
		Head:        pbHead,
		Body:        pbBody,
		Expressions: pbExpressions,
	}, nil
}

func protoRuleToTokenRuleV2(input *pb.RuleV2) (*datalog.Rule, error) {
	body := make([]datalog.Predicate, len(input.Body))
	for i, pb := range input.Body {
		b, err := protoPredicateToTokenPredicateV2(pb)
		if err != nil {
			return nil, err
		}
		body[i] = *b
	}

	expressions := make([]datalog.Expression, len(input.Expressions))
	for i, pbExpression := range input.Expressions {
		e, err := protoExpressionToTokenExpressionV2(pbExpression)
		if err != nil {
			return nil, err
		}
		expressions[i] = e
	}

	head, err := protoPredicateToTokenPredicateV2(input.Head)
	if err != nil {
		return nil, err
	}
	return &datalog.Rule{
		Head:        *head,
		Body:        body,
		Expressions: expressions,
	}, nil
}

func tokenExpressionToProtoExpressionV2(input datalog.Expression) (*pb.ExpressionV2, error) {
	pbExpr := &pb.ExpressionV2{
		Ops: make([]*pb.Op, len(input)),
	}

	for i, op := range input {
		switch op.Type() {
		case datalog.OpTypeValue:
			pbID, err := tokenIDToProtoIDV2(op.(datalog.Value).ID)
			if err != nil {
				return nil, err
			}
			pbExpr.Ops[i] = &pb.Op{Content: &pb.Op_Value{Value: pbID}}
		case datalog.OpTypeUnary:
			pbUnary, err := tokenExprUnaryToProtoExprUnary(op.(datalog.UnaryOp))
			if err != nil {
				return nil, err
			}
			pbExpr.Ops[i] = &pb.Op{Content: &pb.Op_Unary{Unary: pbUnary}}
		case datalog.OpTypeBinary:
			pbBinary, err := tokenExprBinaryToProtoExprBinary(op.(datalog.BinaryOp))
			if err != nil {
				return nil, err
			}
			pbExpr.Ops[i] = &pb.Op{Content: &pb.Op_Binary{Binary: pbBinary}}
		default:
			return nil, fmt.Errorf("biscuit: unsupported expression type: %v", op.Type())
		}
	}
	return pbExpr, nil
}

func protoExpressionToTokenExpressionV2(input *pb.ExpressionV2) (datalog.Expression, error) {
	expr := make(datalog.Expression, len(input.Ops))
	for i, op := range input.Ops {
		switch op.Content.(type) {
		case *pb.Op_Value:
			id, err := protoIDToTokenIDV2(op.GetValue())
			if err != nil {
				return nil, err
			}
			expr[i] = datalog.Value{ID: *id}
		case *pb.Op_Unary:
			op, err := protoExprUnaryToTokenExprUnary(op.GetUnary())
			if err != nil {
				return nil, err
			}
			expr[i] = datalog.UnaryOp{UnaryOpFunc: op}
		case *pb.Op_Binary:
			op, err := protoExprBinaryToTokenExprBinary(op.GetBinary())
			if err != nil {
				return nil, err
			}
			expr[i] = datalog.BinaryOp{BinaryOpFunc: op}
		default:
			return nil, fmt.Errorf("biscuit: unsupported proto expression type: %T", op.Content)
		}
	}
	return expr, nil
}

func tokenExprUnaryToProtoExprUnary(op datalog.UnaryOp) (*pb.OpUnary, error) {
	var pbUnaryKind pb.OpUnary_Kind
	switch op.UnaryOpFunc.Type() {
	case datalog.UnaryNegate:
		pbUnaryKind = pb.OpUnary_Negate
	case datalog.UnaryParens:
		pbUnaryKind = pb.OpUnary_Parens
	case datalog.UnaryLength:
		pbUnaryKind = pb.OpUnary_Length
	default:
		return nil, fmt.Errorf("biscuit: unsupported UnaryOpFunc type: %v", op.UnaryOpFunc.Type())
	}
	return &pb.OpUnary{Kind: &pbUnaryKind}, nil
}

func protoExprUnaryToTokenExprUnary(op *pb.OpUnary) (datalog.UnaryOpFunc, error) {
	var unaryOp datalog.UnaryOpFunc
	switch *op.Kind {
	case pb.OpUnary_Negate:
		unaryOp = datalog.Negate{}
	case pb.OpUnary_Parens:
		unaryOp = datalog.Parens{}
	case pb.OpUnary_Length:
		unaryOp = datalog.Length{}
	default:
		return nil, fmt.Errorf("biscuit: unsupported proto OpUnary type: %v", op.Kind)
	}
	return unaryOp, nil
}

func tokenExprBinaryToProtoExprBinary(op datalog.BinaryOp) (*pb.OpBinary, error) {
	var pbBinaryKind pb.OpBinary_Kind
	switch op.BinaryOpFunc.Type() {
	case datalog.BinaryLessThan:
		pbBinaryKind = pb.OpBinary_LessThan
	case datalog.BinaryLessOrEqual:
		pbBinaryKind = pb.OpBinary_LessOrEqual
	case datalog.BinaryGreaterThan:
		pbBinaryKind = pb.OpBinary_GreaterThan
	case datalog.BinaryGreaterOrEqual:
		pbBinaryKind = pb.OpBinary_GreaterOrEqual
	case datalog.BinaryEqual:
		pbBinaryKind = pb.OpBinary_Equal
	case datalog.BinaryContains:
		pbBinaryKind = pb.OpBinary_Contains
	case datalog.BinaryPrefix:
		pbBinaryKind = pb.OpBinary_Prefix
	case datalog.BinarySuffix:
		pbBinaryKind = pb.OpBinary_Suffix
	case datalog.BinaryRegex:
		pbBinaryKind = pb.OpBinary_Regex
	case datalog.BinaryAdd:
		pbBinaryKind = pb.OpBinary_Add
	case datalog.BinarySub:
		pbBinaryKind = pb.OpBinary_Sub
	case datalog.BinaryMul:
		pbBinaryKind = pb.OpBinary_Mul
	case datalog.BinaryDiv:
		pbBinaryKind = pb.OpBinary_Div
	case datalog.BinaryAnd:
		pbBinaryKind = pb.OpBinary_And
	case datalog.BinaryOr:
		pbBinaryKind = pb.OpBinary_Or
	case datalog.BinaryIntersection:
		pbBinaryKind = pb.OpBinary_Intersection
	case datalog.BinaryUnion:
		pbBinaryKind = pb.OpBinary_Union
	default:
		return nil, fmt.Errorf("biscuit: unsupported BinaryOpFunc type: %v", op.BinaryOpFunc.Type())
	}
	return &pb.OpBinary{Kind: &pbBinaryKind}, nil
}

func protoExprBinaryToTokenExprBinary(op *pb.OpBinary) (datalog.BinaryOpFunc, error) {
	var binaryOp datalog.BinaryOpFunc
	switch *op.Kind {
	case pb.OpBinary_LessThan:
		binaryOp = datalog.LessThan{}
	case pb.OpBinary_GreaterThan:
		binaryOp = datalog.GreaterThan{}
	case pb.OpBinary_LessOrEqual:
		binaryOp = datalog.LessOrEqual{}
	case pb.OpBinary_GreaterOrEqual:
		binaryOp = datalog.GreaterOrEqual{}
	case pb.OpBinary_Equal:
		binaryOp = datalog.Equal{}
	case pb.OpBinary_Contains:
		binaryOp = datalog.Contains{}
	case pb.OpBinary_Prefix:
		binaryOp = datalog.Prefix{}
	case pb.OpBinary_Suffix:
		binaryOp = datalog.Suffix{}
	case pb.OpBinary_Regex:
		binaryOp = datalog.Regex{}
	case pb.OpBinary_Add:
		binaryOp = datalog.Add{}
	case pb.OpBinary_Sub:
		binaryOp = datalog.Sub{}
	case pb.OpBinary_Mul:
		binaryOp = datalog.Mul{}
	case pb.OpBinary_Div:
		binaryOp = datalog.Div{}
	case pb.OpBinary_And:
		binaryOp = datalog.And{}
	case pb.OpBinary_Or:
		binaryOp = datalog.Or{}
	case pb.OpBinary_Intersection:
		binaryOp = datalog.Intersection{}
	case pb.OpBinary_Union:
		binaryOp = datalog.Union{}
	default:
		return nil, fmt.Errorf("biscuit: unsupported proto OpBinary type: %v", op.Kind)
	}
	return binaryOp, nil
}

func tokenCheckToProtoCheckV2(input datalog.Check) (*pb.CheckV2, error) {
	pbQueries := make([]*pb.RuleV2, len(input.Queries))
	for i, query := range input.Queries {
		q, err := tokenRuleToProtoRuleV2(query)
		if err != nil {
			return nil, err
		}
		pbQueries[i] = q
	}

	return &pb.CheckV2{
		Queries: pbQueries,
	}, nil
}

func protoCheckToTokenCheckV2(input *pb.CheckV2) (*datalog.Check, error) {
	queries := make([]datalog.Rule, len(input.Queries))
	for i, query := range input.Queries {
		q, err := protoRuleToTokenRuleV2(query)
		if err != nil {
			return nil, err
		}
		queries[i] = *q
	}

	return &datalog.Check{
		Queries: queries,
	}, nil
}
