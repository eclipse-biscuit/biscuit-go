// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/participle/v2"
	"github.com/alecthomas/participle/v2/lexer"
	"github.com/eclipse-biscuit/biscuit-go/v2"
)

type Comment string

func (c *Comment) Capture(values []string) error {
	if len(values) != 1 {
		return errors.New("parser: invalid comment values")
	}
	if !strings.HasPrefix(values[0], "//") {
		return errors.New("parser: invalid comment prefix")
	}
	*c = Comment(strings.TrimSpace(strings.TrimPrefix(values[0], "//")))
	return nil
}

type Variable string

func (v *Variable) Capture(values []string) error {
	if len(values) != 1 {
		return errors.New("parser: invalid variable values")
	}
	if !strings.HasPrefix(values[0], "$") {
		return errors.New("parser: invalid variable prefix")
	}
	*v = Variable(strings.TrimPrefix(values[0], "$"))
	return nil
}

type Parameter string

type Bool bool

func (b *Bool) Capture(values []string) error {
	if len(values) != 1 {
		return errors.New("parser: invalid bool values")
	}
	v, err := strconv.ParseBool(values[0])
	if err != nil {
		return err
	}
	*b = Bool(v)
	return nil
}

type Block struct {
	Comments []*Comment      `@Comment*`
	Body     []*BlockElement `(@@ ";")*`
}

type BlockElement struct {
	Check     *Check         `@@`
	Predicate *Predicate     `|@@`
	RuleBody  []*RuleElement `("<-" @@ ("," @@)*)?`
}

type ParametersMap map[string]biscuit.Term

func (b *Block) ToBiscuit(parameters ParametersMap) (*biscuit.ParsedBlock, error) {
	facts := biscuit.NewFactSet()
	rules := make([]biscuit.Rule, 0)
	checks := make([]biscuit.Check, 0)

	for _, e := range b.Body {
		switch {
		case e.Check != nil:
			c, err := e.Check.ToBiscuit(parameters)
			if err != nil {
				return nil, err
			}
			checks = append(checks, *c)
		case e.Predicate != nil && e.RuleBody != nil:
			rule := Rule{
				Head: e.Predicate,
				Body: e.RuleBody,
			}
			r, err := rule.ToBiscuit(parameters)
			if err != nil {
				return nil, err
			}
			rules = append(rules, *r)
		default:
			p, err := e.Predicate.ToBiscuit(parameters)
			if err != nil {
				return nil, err
			}
			facts.Insert(biscuit.Fact{Predicate: *p})
		}
	}

	return &biscuit.ParsedBlock{
		Facts:  *facts,
		Rules:  rules,
		Checks: checks,
	}, nil
}

type Authorizer struct {
	Comments []*Comment           `@Comment*`
	Body     []*AuthorizerElement `(@@ ";")*`
}

type AuthorizerElement struct {
	Policy       *Policy       `@@`
	BlockElement *BlockElement `|@@`
}

func (b *Authorizer) ToBiscuit(parameters ParametersMap) (*biscuit.ParsedAuthorizer, error) {
	facts := biscuit.NewFactSet()
	rules := make([]biscuit.Rule, 0)
	checks := make([]biscuit.Check, 0)
	policies := make([]biscuit.Policy, 0)

	for _, e := range b.Body {
		if e.BlockElement != nil {
			be := e.BlockElement
			if be.Check != nil {
				c, err := be.Check.ToBiscuit(parameters)
				if err != nil {
					return nil, err
				}
				checks = append(checks, *c)
			} else if be.Predicate != nil && be.RuleBody != nil {
				rule := Rule{
					Head: be.Predicate,
					Body: be.RuleBody,
				}
				r, err := rule.ToBiscuit(parameters)
				if err != nil {
					return nil, err
				}
				rules = append(rules, *r)
			} else {
				p, err := be.Predicate.ToBiscuit(parameters)
				if err != nil {
					return nil, err
				}
				facts.Insert(biscuit.Fact{Predicate: *p})
			}
		} else if e.Policy != nil {
			p, err := e.Policy.ToBiscuit(parameters)
			if err != nil {
				return nil, err
			}
			policies = append(policies, *p)
		}
	}

	return &biscuit.ParsedAuthorizer{
		Policies: policies,
		Block: biscuit.ParsedBlock{
			Facts:  *facts,
			Rules:  rules,
			Checks: checks,
		},
	}, nil
}

type PublicKey struct {
	Algorithm string
	HexBytes  string
}

func (pk *PublicKey) Capture(values []string) error {
	parts := strings.Split(values[0], "/")
	if len(parts) != 2 {
		return fmt.Errorf("parser: invalid origin element: %s", values[0])
	}
	pk.Algorithm = parts[0]
	pk.HexBytes = parts[1]
	return nil
}

type Origin struct {
	Authority *string    `@"authority"`
	Previous  *string    `| @"previous"`
	PublicKey *PublicKey `| @PublicKey`
}

func (oc *Origin) ToBiscuit(_ ParametersMap) (*biscuit.Scope, error) {
	if oc.Authority != nil {
		return &biscuit.Scope{Type: biscuit.AuthorityScopeType}, nil
	}
	if oc.Previous != nil {
		return &biscuit.Scope{Type: biscuit.PreviousScopeType}, nil
	}
	if oc.PublicKey != nil {
		pubKey, err := biscuit.NewPublicKey(
			oc.PublicKey.Algorithm,
			oc.PublicKey.HexBytes,
		)
		if err != nil {
			return nil, fmt.Errorf("parser: invalid public key `%s` %w", oc.PublicKey.HexBytes, err)
		}

		return &biscuit.Scope{
			Type:      biscuit.PublicKeyScopeType,
			PublicKey: pubKey,
		}, nil
	}
	return nil, errors.New("parser: nil origin")
}

type OriginClause struct {
	Origin []*Origin `"trusting" @@ ("," @@)*`
}

func (oc *OriginClause) ToBiscuit(parameters ParametersMap) ([]biscuit.Scope, error) {
	if oc.Origin == nil {
		return []biscuit.Scope{}, nil
	}
	origins := make([]biscuit.Scope, len(oc.Origin))
	for i, parserOrigin := range oc.Origin {
		biscuitOrigin, err := parserOrigin.ToBiscuit(parameters)
		if err != nil {
			return nil, err
		}
		origins[i] = *biscuitOrigin
	}
	return origins, nil
}

type Rule struct {
	Comments []*Comment     `@Comment*`
	Head     *Predicate     `@@`
	Body     []*RuleElement `"<-" @@ ("," @@)*`
	Origin   *OriginClause  `@@?`
}

type RuleElement struct {
	Predicate  *Predicate  `@@`
	Expression *Expression `|@@`
}

type Predicate struct {
	Name *string `@Ident`
	IDs  []*Term `"(" (@@ ("," @@)*)* ")"`
}

type Check struct {
	CheckIf  *CheckIf  `@@`
	CheckAll *CheckAll `|@@`
	RejectIf *RejectIf `|@@`
}

type CheckIf struct {
	Queries []*CheckQuery `"check if" @@ ( "or" @@ )*`
	Origin  *OriginClause `@@?`
}

type CheckAll struct {
	Queries []*CheckQuery `"check all" @@ ( "or" @@ )*`
	Origin  *OriginClause `@@?`
}

type RejectIf struct {
	Queries []*CheckQuery `"reject if" @@ ( "or" @@ )*`
	Origin  *OriginClause `@@?`
}

type CheckQuery struct {
	Body []*RuleElement `@@ ("," @@)*`
}

type Policy struct {
	Allow *Allow `@@`
	Deny  *Deny  `|@@`
}

type Allow struct {
	Queries []*CheckQuery `"allow if" @@ ( "or" @@ )*`
}

type Deny struct {
	Queries []*CheckQuery `"deny if" @@ ( "or" @@ )*`
}

type Term struct {
	Variable  *Variable  `@Variable`
	Bytes     *HexString `| @@`
	String    *string    `| @String`
	Date      *string    `| @DateTime`
	Integer   *int64     `| @Int`
	Bool      *Bool      `| @Bool`
	Parameter *Parameter `| "{" @Ident "}"`
	EmptySet  *string    `| @("{" "," "}")`
	Set       []*Term    `| "{" @@ ("," @@)* ","? "}"`
}

type Value struct {
	Number        *float64    `  @(Float|Int)`
	Variable      *string     `| @Ident`
	Parameter     *Parameter  `| @Parameter`
	Subexpression *Expression `| "(" @@ ")"`
}

type Operator int

const (
	OpMul Operator = iota
	OpDiv
	OpAdd
	OpSub
	OpAnd
	OpOr
	OpLessOrEqual
	OpGreaterOrEqual
	OpLessThan
	OpGreaterThan
	OpEqual
	OpNotEqual
	OpHeterogeneousEqual
	OpHeterogeneousNotEqual
	OpContains
	OpPrefix
	OpSuffix
	OpMatches
	OpIntersection
	OpUnion
	OpLength
	OpNegate
)

var operatorMap = map[string]Operator{
	"+":            OpAdd,
	"-":            OpSub,
	"*":            OpMul,
	"/":            OpDiv,
	"&&":           OpAnd,
	"||":           OpOr,
	"<=":           OpLessOrEqual,
	">=":           OpGreaterOrEqual,
	"<":            OpLessThan,
	">":            OpGreaterThan,
	"==":           OpHeterogeneousEqual,
	"!=":           OpHeterogeneousNotEqual,
	"===":          OpEqual,
	"!==":          OpNotEqual,
	"!":            OpNegate,
	"contains":     OpContains,
	"starts_with":  OpPrefix,
	"ends_with":    OpSuffix,
	"matches":      OpMatches,
	"intersection": OpIntersection,
	"union":        OpUnion,
	"length":       OpLength,
}

func (o *Operator) Capture(s []string) error {
	*o = operatorMap[s[0]]
	return nil
}

type Expression struct {
	Left  *Expr1     `@@`
	Right []*OpExpr1 `@@*`
}

type OpExpr1 struct {
	Operator Operator `@("||")`
	Expr1    *Expr1   `@@`
}

type Expr1 struct {
	Left  *Expr2     `@@`
	Right []*OpExpr2 `@@*`
}

type OpExpr2 struct {
	Operator Operator `@("&&")`
	Expr2    *Expr2   `@@`
}

type Expr2 struct {
	Left  *Expr3   `@@`
	Right *OpExpr3 `@@?`
}

type OpExpr3 struct {
	Operator Operator `@("<=" | ">=" | "<" | ">" | "==" | "!=" | "===" | "!==")`
	Expr3    *Expr3   `@@`
}

type Expr3 struct {
	Left  *Expr4     `@@`
	Right []*OpExpr4 `@@*`
}

type OpExpr4 struct {
	Operator Operator `@("+" | "-")`
	Expr4    *Expr4   `@@`
}

type Expr4 struct {
	Left  *Expr5     `@@`
	Right []*OpExpr5 `@@*`
}

type OpExpr5 struct {
	Operator Operator `@("*" | "/")`
	Expr5    *Expr5   `@@`
}

type Expr5 struct {
	Operator *Operator `@("!")?`
	Expr6    *Expr6    `@@`
}

type Expr6 struct {
	Left  *ExprTerm  `@@`
	Right []*OpExpr7 `@@*`
}

type OpExpr7 struct {
	Operator   Operator    `Dot @("matches" | "starts_with" | "ends_with" | "contains" | "union" | "intersection" | "length")`
	Expression *Expression `"(" @@? ")"`
}

type ExprTerm struct {
	Term       *Term       `@@`
	Expression *Expression `| "(" @@? ")"`
}

func (e *Expression) ToExpr(expr *biscuit.Expression, parameters ParametersMap) {
	e.Left.ToExpr(expr, parameters)

	for _, op := range e.Right {
		op.ToExpr(expr, parameters)
	}
}

func (e *Expr1) ToExpr(expr *biscuit.Expression, parameters ParametersMap) {
	e.Left.ToExpr(expr, parameters)

	for _, op := range e.Right {
		op.ToExpr(expr, parameters)
	}
}

func (e *Expr2) ToExpr(expr *biscuit.Expression, parameters ParametersMap) {
	e.Left.ToExpr(expr, parameters)
	if e.Right != nil {

		e.Right.ToExpr(expr, parameters)
	}
}

func (e *Expr3) ToExpr(expr *biscuit.Expression, parameters ParametersMap) {
	e.Left.ToExpr(expr, parameters)

	for _, op := range e.Right {
		op.ToExpr(expr, parameters)
	}
}

func (e *Expr4) ToExpr(expr *biscuit.Expression, parameters ParametersMap) {
	e.Left.ToExpr(expr, parameters)

	for _, op := range e.Right {
		op.ToExpr(expr, parameters)
	}
}

func (e *Expr5) ToExpr(expr *biscuit.Expression, parameters ParametersMap) {
	e.Expr6.ToExpr(expr, parameters)
	if e.Operator != nil {
		*expr = append(*expr, biscuit.UnaryNegate)
	}
}

func (e *Expr6) ToExpr(expr *biscuit.Expression, parameters ParametersMap) {
	e.Left.ToExpr(expr, parameters)
	for _, op := range e.Right {
		op.ToExpr(expr, parameters)
	}
}

func (e *ExprTerm) ToExpr(expr *biscuit.Expression, parameters ParametersMap) {

	switch {
	case e.Term != nil:
		//FIXME: error management
		term, _ := e.Term.ToBiscuit(parameters)
		*expr = append(*expr, biscuit.Value{Term: term})
	case e.Expression != nil:
		e.Expression.ToExpr(expr, parameters)
		*expr = append(*expr, biscuit.UnaryParens)
	}

}

func (e *OpExpr1) ToExpr(expr *biscuit.Expression, parameters ParametersMap) {
	e.Expr1.ToExpr(expr, parameters)
	e.Operator.ToExpr(expr)
}

func (e *OpExpr2) ToExpr(expr *biscuit.Expression, parameters ParametersMap) {
	e.Expr2.ToExpr(expr, parameters)
	e.Operator.ToExpr(expr)
}

func (e *OpExpr3) ToExpr(expr *biscuit.Expression, parameters ParametersMap) {
	e.Expr3.ToExpr(expr, parameters)
	e.Operator.ToExpr(expr)
}

func (e *OpExpr4) ToExpr(expr *biscuit.Expression, parameters ParametersMap) {
	e.Expr4.ToExpr(expr, parameters)
	e.Operator.ToExpr(expr)
}

func (e *OpExpr5) ToExpr(expr *biscuit.Expression, parameters ParametersMap) {
	e.Expr5.ToExpr(expr, parameters)
	e.Operator.ToExpr(expr)
}

func (e *OpExpr7) ToExpr(expr *biscuit.Expression, parameters ParametersMap) {
	if e.Expression != nil {
		e.Expression.ToExpr(expr, parameters)
	}
	e.Operator.ToExpr(expr)
}

func (op *Operator) ToExpr(expr *biscuit.Expression) {

	var biscuit_op biscuit.Op
	switch *op {
	case OpAnd:
		biscuit_op = biscuit.BinaryAnd
	case OpOr:
		biscuit_op = biscuit.BinaryOr
	case OpMul:
		biscuit_op = biscuit.BinaryMul
	case OpDiv:
		biscuit_op = biscuit.BinaryDiv
	case OpAdd:
		biscuit_op = biscuit.BinaryAdd
	case OpSub:
		biscuit_op = biscuit.BinarySub
	case OpLessOrEqual:
		biscuit_op = biscuit.BinaryLessOrEqual
	case OpGreaterOrEqual:
		biscuit_op = biscuit.BinaryGreaterOrEqual
	case OpLessThan:
		biscuit_op = biscuit.BinaryLessThan
	case OpGreaterThan:
		biscuit_op = biscuit.BinaryGreaterThan
	case OpEqual:
		biscuit_op = biscuit.BinaryEqual
	case OpContains:
		biscuit_op = biscuit.BinaryContains
	case OpPrefix:
		biscuit_op = biscuit.BinaryPrefix
	case OpSuffix:
		biscuit_op = biscuit.BinarySuffix
	case OpMatches:
		biscuit_op = biscuit.BinaryRegex
	case OpLength:
		biscuit_op = biscuit.UnaryLength
	case OpIntersection:
		biscuit_op = biscuit.BinaryIntersection
	case OpUnion:
		biscuit_op = biscuit.BinaryUnion
	}

	*expr = append(*expr, biscuit_op)
}

type HexString string

func (h *HexString) Parse(lex *lexer.PeekingLexer) error {
	token := lex.Peek()
	if !strings.HasPrefix(token.Value, "hex:") {
		return participle.NextMatch
	}
	lex.Next()
	*h = HexString(token.Value[4:])
	return nil
}

func (h *HexString) Decode() ([]byte, error) {
	return hex.DecodeString(string(*h))
}

func (h *HexString) String() string {
	return string(*h)
}

func (p *Predicate) ToBiscuit(parameters ParametersMap) (*biscuit.Predicate, error) {
	terms := make([]biscuit.Term, 0, len(p.IDs))
	for _, a := range p.IDs {
		biscuitTerm, err := a.ToBiscuit(parameters)
		if err != nil {
			return nil, err
		}
		terms = append(terms, biscuitTerm)
	}

	return &biscuit.Predicate{
		Name: *p.Name,
		IDs:  terms,
	}, nil
}

func (a *Term) ToBiscuit(parameters ParametersMap) (biscuit.Term, error) {
	var biscuitTerm biscuit.Term
	switch {
	case a.Integer != nil:
		biscuitTerm = biscuit.Integer(*a.Integer)
	case a.String != nil:
		biscuitTerm = biscuit.String(*a.String)
	case a.Variable != nil:
		biscuitTerm = biscuit.Variable(*a.Variable)
	case a.Date != nil:
		date, err := time.Parse(time.RFC3339, *a.Date)
		if err != nil {
			return nil, fmt.Errorf("parser: failed to decode date: %v", err)
		}

		biscuitTerm = biscuit.Date(date)
	case a.Bytes != nil:
		b, err := a.Bytes.Decode()
		if err != nil {
			return nil, fmt.Errorf("parser: failed to decode hex string: %v", err)
		}
		biscuitTerm = biscuit.Bytes(b)
	case a.Bool != nil:
		biscuitTerm = biscuit.Bool(*a.Bool)
	case a.EmptySet != nil:
		biscuitTerm = biscuit.NewSet()
	case a.Set != nil:
		biscuitSet := biscuit.NewSet()
		for _, term := range a.Set {
			setTerm, err := term.ToBiscuit(parameters)
			if err != nil {
				return nil, err
			}
			if setTerm.Type() == biscuit.TermTypeVariable {
				return nil, ErrVariableInSet
			}
			biscuitSet.Insert(setTerm)
		}
		biscuitTerm = biscuitSet
	case a.Parameter != nil:
		var paramName string = string(*(a.Parameter))
		paramValue := parameters[paramName]
		if paramValue == nil {
			return nil, fmt.Errorf("parser: unbound parameter: %s", paramName)
		}
		biscuitTerm = paramValue

	default:
		return nil, errors.New("parser: unsupported predicate, must be one of integer, string, variable, or bytes")
	}

	return biscuitTerm, nil
}

func (r *Rule) ToBiscuit(parameters ParametersMap) (*biscuit.Rule, error) {
	body := []biscuit.Predicate{}
	expressions := make([]biscuit.Expression, 0)

	for _, p := range r.Body {
		switch {
		case p.Predicate != nil:
			{
				predicate, err := (*p.Predicate).ToBiscuit(parameters)
				if err != nil {
					return nil, err
				}
				body = append(body, *predicate)
			}
		case p.Expression != nil:
			{
				var expr biscuit.Expression
				(*p.Expression).ToExpr(&expr, parameters)

				expressions = append(expressions, expr)
			}
		}
	}

	head, err := r.Head.ToBiscuit(parameters)
	if err != nil {
		return nil, err
	}

	var origin []biscuit.Scope
	if r.Origin != nil {
		origin, err = r.Origin.ToBiscuit(parameters)
		if err != nil {
			return nil, err
		}
	}

	return &biscuit.Rule{
		Head:        *head,
		Body:        body,
		Expressions: expressions,
		Scopes:      origin,
	}, nil
}

func (c *Check) ToBiscuit(parameters ParametersMap) (*biscuit.Check, error) {
	// Convert origin clause to scope
	var scopes []biscuit.Scope
	var origin *OriginClause

	// Determine the check kind
	var parsedQueries []*CheckQuery
	var kind biscuit.CheckKind
	switch {
	case c.CheckIf != nil:
		parsedQueries = c.CheckIf.Queries
		kind = biscuit.CheckOne
		origin = c.CheckIf.Origin
	case c.CheckAll != nil:
		parsedQueries = c.CheckAll.Queries
		kind = biscuit.CheckAll
		origin = c.CheckAll.Origin
	case c.RejectIf != nil:
		parsedQueries = c.RejectIf.Queries
		kind = biscuit.CheckReject
		origin = c.RejectIf.Origin
	default:
		// If we get here, it is probably an internal parser error
		return nil, errors.New("parser: unsupported check, must be check if, check all, or reject if")
	}

	// Determine the origin
	var err error
	if origin != nil {
		scopes, err = origin.ToBiscuit(parameters)
		if err != nil {
			return nil, err
		}
	}

	// Build queries, applying scopes as we go
	queries := make([]biscuit.Rule, len(parsedQueries))
	for i, q := range parsedQueries {
		r, err := q.ToBiscuit(parameters)
		if err != nil {
			return nil, err
		}

		if scopes != nil {
			r.Scopes = scopes
		}

		queries[i] = *r
	}

	return &biscuit.Check{
		Queries: queries,
		Kind:    kind,
	}, nil
}

func (r *CheckQuery) ToBiscuit(parameters ParametersMap) (*biscuit.Rule, error) {
	body := []biscuit.Predicate{}
	expressions := make([]biscuit.Expression, 0)

	for _, p := range r.Body {
		switch {
		case p.Predicate != nil:
			{
				predicate, err := (*p.Predicate).ToBiscuit(parameters)
				if err != nil {
					return nil, err
				}
				body = append(body, *predicate)
			}
		case p.Expression != nil:
			{
				var expr biscuit.Expression
				(*p.Expression).ToExpr(&expr, parameters)

				expressions = append(expressions, expr)
			}
		}
	}

	head := &biscuit.Predicate{
		Name: "query",
		IDs:  []biscuit.Term{},
	}

	return &biscuit.Rule{
		Head:        *head,
		Body:        body,
		Expressions: expressions,
	}, nil
}

func (p *Policy) ToBiscuit(parameters ParametersMap) (*biscuit.Policy, error) {
	var parsedQueries []*CheckQuery
	var kind biscuit.PolicyKind
	switch {
	case p.Allow != nil:
		{
			parsedQueries = p.Allow.Queries
			kind = biscuit.PolicyKindAllow
			break
		}
	case p.Deny != nil:
		{
			parsedQueries = p.Deny.Queries
			kind = biscuit.PolicyKindDeny
			break
		}
	}
	queries := make([]biscuit.Rule, 0, len(parsedQueries))
	for _, q := range parsedQueries {
		r, err := q.ToBiscuit(parameters)
		if err != nil {
			return nil, err
		}

		queries = append(queries, *r)
	}

	return &biscuit.Policy{
		Queries: queries,
		Kind:    kind,
	}, nil
}
