// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package datalog

import (
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

// maxStackSize defines the maximum number of elements that can be stored on the stack.
// Trying to store more than maxStackSize elements returns an error.
const maxStackSize = 1000

var (
	ErrExprDivByZero = errors.New("datalog: Div by zero")
	ErrInt64Overflow = errors.New("datalog: expression overflowed int64")
)

type Expression []Op

func (e *Expression) Evaluate(values map[Variable]*Term, symbols *SymbolTable) (Term, error) {
	s := &stack{}

	for _, op := range *e {
		switch op.Type() {
		case OpTypeValue:
			id := op.(Value).ID
			switch id.Type() {
			case TermTypeVariable:
				idptr, ok := values[id.(Variable)]
				if !ok {
					return nil, fmt.Errorf("datalog: expressions: unknown variable %d", id.(Variable))
				}
				id = *idptr
			default: // do nothing
			}
			err := s.Push(id)
			if err != nil {
				return nil, fmt.Errorf("datalog: expressions: stack overflow")
			}
		case OpTypeUnary:
			v, err := s.Pop()
			if err != nil {
				return nil, fmt.Errorf("datalog: expressions: failed to pop unary value: %w", err)
			}

			res, err := op.(UnaryOp).Eval(v, symbols)
			if err != nil {
				return nil, fmt.Errorf("datalog: expressions: unary eval failed: %w", err)
			}
			err = s.Push(res)
			if err != nil {
				return nil, fmt.Errorf("datalog: expressions: stack overflow")
			}
		case OpTypeBinary:
			right, err := s.Pop()
			if err != nil {
				return nil, fmt.Errorf("datalog: expressions: failed to pop binary right value: %w", err)
			}
			left, err := s.Pop()
			if err != nil {
				return nil, fmt.Errorf("datalog: expressions: failed to pop binary left value: %w", err)
			}

			res, err := op.(BinaryOp).Eval(left, right, symbols)
			if err != nil {
				return nil, fmt.Errorf("datalog: expressions: binary eval failed: %w", err)
			}
			err = s.Push(res)
			if err != nil {
				return nil, fmt.Errorf("datalog: expressions: stack overflow")
			}
		default:
			return nil, fmt.Errorf("datalog: expressions: unsupported Op: %v", op.Type())
		}
	}

	// after processing all operations, there must be a single value left in the stack
	if len(*s) != 1 {
		return nil, fmt.Errorf("datalog: expressions: invalid resulting stack: %#v", *s)
	}

	return s.Pop()
}

func (e *Expression) Print(symbols *SymbolTable) string {
	s := &stringstack{}

	for _, op := range *e {
		switch op.Type() {
		case OpTypeValue:
			id := op.(Value).ID
			debug := SymbolDebugger{symbols}
			s.Push(debug.Term(id))
		case OpTypeUnary:
			v, err := s.Pop()
			if err != nil {
				return "<invalid expression: unary operation failed to pop value>"
			}
			res := op.(UnaryOp).Print(v)
			err = s.Push(res)
			if err != nil {
				return "<invalid expression: stack overflow>"
			}
		case OpTypeBinary:
			right, err := s.Pop()
			if err != nil {
				return "<invalid expression: binary operation failed to pop right value>"
			}
			left, err := s.Pop()
			if err != nil {
				return "<invalid expression: binary operation failed to pop left value>"
			}
			res := op.(BinaryOp).Print(left, right)
			err = s.Push(res)
			if err != nil {
				return "<invalid expression: stack overflow>"
			}
		default:
			return fmt.Sprintf("<invalid expression: unsupported op type %v>", op.Type())
		}
	}

	if len(*s) == 1 {
		v, err := s.Pop()
		if err != nil {
			return "<invalid expression: failed to pop result value>"
		}
		return v
	}

	return "<invalid expression: invalid resulting stack>"
}

type OpType byte

const (
	OpTypeValue OpType = iota
	OpTypeUnary
	OpTypeBinary
)

type Op interface {
	Type() OpType
}

type Value struct {
	ID Term
}

func (v Value) Type() OpType {
	return OpTypeValue
}

type UnaryOp struct {
	UnaryOpFunc
}

func (UnaryOp) Type() OpType {
	return OpTypeUnary
}
func (op UnaryOp) Print(value string) string {
	var out string
	switch op.UnaryOpFunc.Type() {
	case UnaryNegate:
		out = fmt.Sprintf("!%s", value)
	case UnaryParens:
		out = fmt.Sprintf("(%s)", value)
	case UnaryLength:
		out = fmt.Sprintf("%s.length()", value)
	default:
		out = fmt.Sprintf("unknown(%s)", value)
	}
	return out
}

type UnaryOpFunc interface {
	Type() UnaryOpType
	Eval(value Term, symbols *SymbolTable) (Term, error)
}

type UnaryOpType byte

const (
	UnaryNegate UnaryOpType = iota
	UnaryParens
	UnaryLength
)

// Negate returns the negation of a value.
// It only accepts a Bool value.
type Negate struct{}

func (Negate) Type() UnaryOpType {
	return UnaryNegate
}
func (Negate) Eval(value Term, _ *SymbolTable) (Term, error) {
	var out Term
	switch value.Type() {
	case TermTypeBool:
		out = !value.(Bool)
	default:
		return nil, fmt.Errorf("datalog: unexpected Negate value type: %d", value.Type())
	}

	return out, nil
}

// Parens allows expression priority and grouping (like parenthesis in math operations)
// it is a no-op, but is used to print back the expressions properly, putting their value
// inside parenthesis.
type Parens struct{}

func (Parens) Type() UnaryOpType {
	return UnaryParens
}
func (Parens) Eval(value Term, _ *SymbolTable) (Term, error) {
	return value, nil
}

// Length returns the length of a value.
// It accepts String, Bytes and Set
type Length struct{}

func (Length) Type() UnaryOpType {
	return UnaryLength
}
func (Length) Eval(value Term, symbols *SymbolTable) (Term, error) {
	var out Term
	switch value.Type() {
	case TermTypeString:
		str := symbols.Str(value.(String))
		out = Integer(len(str))
	case TermTypeBytes:
		out = Integer(len(value.(Bytes)))
	case TermTypeSet:
		out = Integer(len(value.(TermSet)))
	default:
		return nil, fmt.Errorf("datalog: unexpected Length value type: %d", value.Type())
	}
	return out, nil
}

type BinaryOp struct {
	BinaryOpFunc
}

func (BinaryOp) Type() OpType {
	return OpTypeBinary
}
func (op BinaryOp) Print(left, right string) string {
	var out string
	switch op.BinaryOpFunc.Type() {
	case BinaryLessThan:
		out = fmt.Sprintf("%s < %s", left, right)
	case BinaryLessOrEqual:
		out = fmt.Sprintf("%s <= %s", left, right)
	case BinaryGreaterThan:
		out = fmt.Sprintf("%s > %s", left, right)
	case BinaryGreaterOrEqual:
		out = fmt.Sprintf("%s >= %s", left, right)
	case BinaryEqual:
		out = fmt.Sprintf("%s == %s", left, right)
	case BinaryContains:
		out = fmt.Sprintf("%s.contains(%s)", left, right)
	case BinaryPrefix:
		out = fmt.Sprintf("%s.starts_with(%s)", left, right)
	case BinarySuffix:
		out = fmt.Sprintf("%s.ends_with(%s)", left, right)
	case BinaryRegex:
		out = fmt.Sprintf("%s.matches(%s)", left, right)
	case BinaryAdd:
		out = fmt.Sprintf("%s + %s", left, right)
	case BinarySub:
		out = fmt.Sprintf("%s - %s", left, right)
	case BinaryMul:
		out = fmt.Sprintf("%s * %s", left, right)
	case BinaryDiv:
		out = fmt.Sprintf("%s / %s", left, right)
	case BinaryAnd:
		out = fmt.Sprintf("%s && %s", left, right)
	case BinaryOr:
		out = fmt.Sprintf("%s || %s", left, right)
	case BinaryIntersection:
		out = fmt.Sprintf("%s.intersection(%s)", left, right)
	case BinaryUnion:
		out = fmt.Sprintf("%s.union(%s)", left, right)
	default:
		out = fmt.Sprintf("unknown(%s, %s)", left, right)
	}
	return out
}

type BinaryOpFunc interface {
	Type() BinaryOpType
	Eval(left, right Term, symbols *SymbolTable) (Term, error)
}

type BinaryOpType byte

const (
	BinaryLessThan BinaryOpType = iota
	BinaryLessOrEqual
	BinaryGreaterThan
	BinaryGreaterOrEqual
	BinaryEqual
	BinaryContains
	BinaryPrefix
	BinarySuffix
	BinaryRegex
	BinaryAdd
	BinarySub
	BinaryMul
	BinaryDiv
	BinaryAnd
	BinaryOr
	BinaryIntersection
	BinaryUnion
)

// LessThan returns true when left is less than right.
// It requires left and right to have the same concrete type
// and only accepts Integer.
type LessThan struct{}

func (LessThan) Type() BinaryOpType {
	return BinaryLessThan
}
func (LessThan) Eval(left Term, right Term, _ *SymbolTable) (Term, error) {
	if g, w := left.Type(), right.Type(); g != w {
		return nil, fmt.Errorf("datalog: LessThan type mismatch: %d != %d", g, w)
	}

	var out Term
	switch left.Type() {
	case TermTypeInteger:
		out = Bool(left.(Integer) < right.(Integer))
	case TermTypeDate:
		out = Bool(left.(Date) < right.(Date))
	default:
		return nil, fmt.Errorf("datalog: unexpected LessThan value type: %d", left.Type())
	}

	return out, nil
}

// LessOrEqual returns true when left is less or equal than right.
// It requires left and right to have the same concrete type
// and only accepts Integer and Date.
type LessOrEqual struct{}

func (LessOrEqual) Type() BinaryOpType {
	return BinaryLessOrEqual
}
func (LessOrEqual) Eval(left Term, right Term, _ *SymbolTable) (Term, error) {
	if g, w := left.Type(), right.Type(); g != w {
		return nil, fmt.Errorf("datalog: LessOrEqual type mismatch: %d != %d", g, w)
	}

	var out Term
	switch left.Type() {
	case TermTypeInteger:
		out = Bool(left.(Integer) <= right.(Integer))
	case TermTypeDate:
		out = Bool(left.(Date) <= right.(Date))
	default:
		return nil, fmt.Errorf("datalog: unexpected LessOrEqual value type: %d", left.Type())
	}

	return out, nil
}

// GreaterThan returns true when left is greater than right.
// It requires left and right to have the same concrete type
// and only accepts Integer.
type GreaterThan struct{}

func (GreaterThan) Type() BinaryOpType {
	return BinaryGreaterThan
}
func (GreaterThan) Eval(left Term, right Term, _ *SymbolTable) (Term, error) {
	if g, w := left.Type(), right.Type(); g != w {
		return nil, fmt.Errorf("datalog: GreaterThan type mismatch: %d != %d", g, w)
	}

	var out Term
	switch left.Type() {
	case TermTypeInteger:
		out = Bool(left.(Integer) > right.(Integer))
	case TermTypeDate:
		out = Bool(left.(Date) > right.(Date))
	default:
		return nil, fmt.Errorf("datalog: unexpected GreaterThan value type: %d", left.Type())
	}

	return out, nil
}

// GreaterOrEqual returns true when left is greater than right.
// It requires left and right to have the same concrete type
// and only accepts Integer and Date.
type GreaterOrEqual struct{}

func (GreaterOrEqual) Type() BinaryOpType {
	return BinaryGreaterOrEqual
}
func (GreaterOrEqual) Eval(left Term, right Term, _ *SymbolTable) (Term, error) {
	if g, w := left.Type(), right.Type(); g != w {
		return nil, fmt.Errorf("datalog: GreaterOrEqual type mismatch: %d != %d", g, w)
	}

	var out Term
	switch left.Type() {
	case TermTypeInteger:
		out = Bool(left.(Integer) >= right.(Integer))
	case TermTypeDate:
		out = Bool(left.(Date) >= right.(Date))
	default:
		return nil, fmt.Errorf("datalog: unexpected GreaterOrEqual value type: %d", left.Type())
	}

	return out, nil
}

// Equal returns true when left and right are equal.
// It requires left and right to have the same concrete type
// and only accepts Integer, Bytes or String.
type Equal struct{}

func (Equal) Type() BinaryOpType {
	return BinaryEqual
}
func (Equal) Eval(left Term, right Term, _ *SymbolTable) (Term, error) {
	if g, w := left.Type(), right.Type(); g != w {
		return nil, fmt.Errorf("datalog: Equal type mismatch: %d != %d", g, w)
	}

	switch left.Type() {
	case TermTypeInteger:
	case TermTypeBytes:
	case TermTypeString:
	case TermTypeDate:
	case TermTypeBool:
	case TermTypeSet:

	default:
		return nil, fmt.Errorf("datalog: unexpected Equal value type: %d", left.Type())
	}

	return Bool(left.Equal(right)), nil
}

// Contains returns true when the right value exists in the left Set.
// The right value must be an Integer, Bytes, String or Symbol.
// The left value must be a Set, containing elements of right type.
type Contains struct{}

func (Contains) Type() BinaryOpType {
	return BinaryContains
}
func (Contains) Eval(left Term, right Term, symbols *SymbolTable) (Term, error) {
	sleft, ok := left.(String)
	if ok {
		sright, ok := right.(String)
		if !ok {
			return nil, fmt.Errorf("datalog: Contains requires right value to be a String, got %T", right)
		}

		return Bool(strings.Contains(symbols.Str(sleft), symbols.Str(sright))), nil
	}

	switch right.Type() {
	case TermTypeInteger:
	case TermTypeBytes:
	case TermTypeString:
	case TermTypeDate:
	case TermTypeBool:
	case TermTypeSet:

	default:
		return nil, fmt.Errorf("datalog: unexpected Contains right value type: %d", right.Type())
	}

	set, ok := left.(TermSet)
	if !ok {
		return nil, errors.New("datalog: Contains left value must be a Set")
	}

	rhsset, ok := right.(TermSet)

	if ok {
		for _, rhselt := range rhsset {
			rhsinlhs := false
			for _, lhselt := range set {
				if lhselt.Equal(rhselt) {
					rhsinlhs = true
				}
			}
			if !rhsinlhs {
				return Bool(false), nil
			}
		}
		return Bool(true), nil
	}

	for _, elt := range set {
		if right.Equal(elt) {
			return Bool(true), nil
		}
	}

	return Bool(false), nil
}

// Intersection returns the intersection of two sets
type Intersection struct{}

func (Intersection) Type() BinaryOpType {
	return BinaryIntersection
}
func (Intersection) Eval(left Term, right Term, _ *SymbolTable) (Term, error) {
	set, ok := left.(TermSet)
	if !ok {
		return nil, errors.New("datalog: Intersection left value must be a Set")
	}

	set2, ok := right.(TermSet)
	if !ok {
		return nil, errors.New("datalog: Intersection rightt value must be a Set")
	}

	return set.Intersect(set2), nil
}

// Intersection returns the intersection of two sets
type Union struct{}

func (Union) Type() BinaryOpType {
	return BinaryUnion
}
func (Union) Eval(left Term, right Term, _ *SymbolTable) (Term, error) {
	set, ok := left.(TermSet)
	if !ok {
		return nil, errors.New("datalog: Union left value must be a Set")
	}

	set2, ok := right.(TermSet)
	if !ok {
		return nil, errors.New("datalog: Union rightt value must be a Set")
	}

	return set.Union(set2), nil
}

// Prefix returns true when the left string starts with the right string.
// left and right must be String.
type Prefix struct{}

func (Prefix) Type() BinaryOpType {
	return BinaryPrefix
}
func (Prefix) Eval(left Term, right Term, symbols *SymbolTable) (Term, error) {
	sleft, ok := left.(String)
	if !ok {
		return nil, fmt.Errorf("datalog: Prefix requires left value to be a String, got %T", left)
	}
	sright, ok := right.(String)
	if !ok {
		return nil, fmt.Errorf("datalog: Prefix requires right value to be a String, got %T", right)
	}

	return Bool(strings.HasPrefix(symbols.Str(sleft), symbols.Str(sright))), nil
}

// Suffix returns true when the left string ends with the right string.
// left and right must be String.
type Suffix struct{}

func (Suffix) Type() BinaryOpType {
	return BinarySuffix
}
func (Suffix) Eval(left Term, right Term, symbols *SymbolTable) (Term, error) {
	sleft, ok := left.(String)
	if !ok {
		return nil, fmt.Errorf("datalog: Suffix requires left value to be a String, got %T", left)
	}
	sright, ok := right.(String)
	if !ok {
		return nil, fmt.Errorf("datalog: Suffix requires right value to be a String, got %T", right)
	}

	return Bool(strings.HasSuffix(symbols.Str(sleft), symbols.Str(sright))), nil
}

// Regex returns true when the right string is a regexp and left matches against it.
// left and right must be String.
type Regex struct{}

func (Regex) Type() BinaryOpType {
	return BinaryRegex
}
func (Regex) Eval(left Term, right Term, symbols *SymbolTable) (Term, error) {
	sleft, ok := left.(String)
	if !ok {
		return nil, fmt.Errorf("datalog: Regex requires left value to be a String, got %T", left)
	}
	sright, ok := right.(String)
	if !ok {
		return nil, fmt.Errorf("datalog: Regex requires right value to be a String, got %T", right)
	}

	re, err := regexp.Compile(symbols.Str(sright))
	if err != nil {
		return nil, fmt.Errorf("datalog: invalid regex: %q: %v", right, err)
	}
	return Bool(re.Match([]byte(symbols.Str(sleft)))), nil
}

// Add performs the addition of left + right and returns the result.
// It requires left and right to be Integer.
type Add struct{}

func (Add) Type() BinaryOpType {
	return BinaryAdd
}
func (Add) Eval(left Term, right Term, symbols *SymbolTable) (Term, error) {
	sleft, ok := left.(String)
	if ok {
		sright, ok := right.(String)
		if !ok {
			return nil, fmt.Errorf("datalog: Add requires right value to be a String, got %T", right)
		}

		s := symbols.Insert(symbols.Str(sleft) + symbols.Str(sright))
		return s, nil
	}

	ileft, ok := left.(Integer)
	if !ok {
		return nil, fmt.Errorf("datalog: Add requires left value to be an Integer, got %T", left)
	}
	iright, ok := right.(Integer)
	if !ok {
		return nil, fmt.Errorf("datalog: Add requires right value to be an Integer, got %T", right)
	}

	bleft := big.NewInt(int64(ileft))
	bright := big.NewInt(int64(iright))
	res := big.NewInt(0)
	res.Add(bleft, bright)

	if !res.IsInt64() {
		return nil, ErrInt64Overflow
	}
	return Integer(res.Int64()), nil
}

// Sub performs the substraction of left - right and returns the result.
// It requires left and right to be Integer.
type Sub struct{}

func (Sub) Type() BinaryOpType {
	return BinarySub
}
func (Sub) Eval(left Term, right Term, _ *SymbolTable) (Term, error) {
	ileft, ok := left.(Integer)
	if !ok {
		return nil, fmt.Errorf("datalog: Sub requires left value to be an Integer, got %T", left)
	}
	iright, ok := right.(Integer)
	if !ok {
		return nil, fmt.Errorf("datalog: Sub requires right value to be an Integer, got %T", right)
	}

	bleft := big.NewInt(int64(ileft))
	bright := big.NewInt(int64(iright))
	res := big.NewInt(0)
	res.Sub(bleft, bright)

	if !res.IsInt64() {
		return nil, ErrInt64Overflow
	}
	return Integer(res.Int64()), nil
}

// Mul performs the multiplication of left * right and returns the result.
// It requires left and right to be Integer.
type Mul struct{}

func (Mul) Type() BinaryOpType {
	return BinaryMul
}
func (Mul) Eval(left Term, right Term, _ *SymbolTable) (Term, error) {
	ileft, ok := left.(Integer)
	if !ok {
		return nil, fmt.Errorf("datalog: Mul requires left value to be an Integer, got %T", left)
	}
	iright, ok := right.(Integer)
	if !ok {
		return nil, fmt.Errorf("datalog: Mul requires right value to be an Integer, got %T", right)
	}

	bleft := big.NewInt(int64(ileft))
	bright := big.NewInt(int64(iright))
	res := big.NewInt(0)
	res.Mul(bleft, bright)

	if !res.IsInt64() {
		return nil, ErrInt64Overflow
	}

	return Integer(res.Int64()), nil
}

// Div performs the division of left / right and returns the result.
// It requires left and right to be Integer.
type Div struct{}

func (Div) Type() BinaryOpType {
	return BinaryDiv
}
func (Div) Eval(left Term, right Term, _ *SymbolTable) (Term, error) {
	ileft, ok := left.(Integer)
	if !ok {
		return nil, fmt.Errorf("datalog: Div requires left value to be an Integer, got %T", left)
	}
	iright, ok := right.(Integer)
	if !ok {
		return nil, fmt.Errorf("datalog: Div requires right value to be an Integer, got %T", right)
	}

	if iright == 0 {
		return nil, ErrExprDivByZero
	}

	return Integer(ileft / iright), nil
}

// And performs a logical AND between left and right and returns a Bool.
// It requires left and right to be Bool.
type And struct{}

func (And) Type() BinaryOpType {
	return BinaryAnd
}
func (And) Eval(left Term, right Term, _ *SymbolTable) (Term, error) {
	bleft, ok := left.(Bool)
	if !ok {
		return nil, fmt.Errorf("datalog: And requires left value to be a Bool, got %T", left)
	}
	bright, ok := right.(Bool)
	if !ok {
		return nil, fmt.Errorf("datalog: And requires right value to be a Bool, got %T", right)
	}

	return Bool(bleft && bright), nil
}

// Or performs a logical OR between left and right and returns a Bool.
// It requires left and right to be Bool.
type Or struct{}

func (Or) Type() BinaryOpType {
	return BinaryOr
}
func (Or) Eval(left Term, right Term, _ *SymbolTable) (Term, error) {
	bleft, ok := left.(Bool)
	if !ok {
		return nil, fmt.Errorf("datalog: Or requires left value to be a Bool, got %T", left)
	}
	bright, ok := right.(Bool)
	if !ok {
		return nil, fmt.Errorf("datalog: Or requires right value to be a Bool, got %T", right)
	}

	return Bool(bleft || bright), nil
}

type stack []Term

func (s *stack) Push(v Term) error {
	if len(*s) >= maxStackSize {
		return errors.New("stack overflow")
	}

	*s = append(*s, v)

	return nil
}

func (s *stack) Pop() (Term, error) {
	if len(*s) == 0 {
		return nil, errors.New("cannot pop from empty stack")
	}

	e := (*s)[len(*s)-1]
	*s = (*s)[:len(*s)-1]

	return e, nil
}

type stringstack []string

func (s *stringstack) Push(v string) error {
	if len(*s) >= maxStackSize {
		return errors.New("stack overflow")
	}

	*s = append(*s, v)

	return nil
}

func (s *stringstack) Pop() (string, error) {
	if len(*s) == 0 {
		return "", errors.New("cannot pop from empty stack")
	}

	e := (*s)[len(*s)-1]
	*s = (*s)[:len(*s)-1]

	return e, nil
}
