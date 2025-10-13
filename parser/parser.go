// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"errors"

	"github.com/alecthomas/participle/v2"
	"github.com/alecthomas/participle/v2/lexer"
	"github.com/eclipse-biscuit/biscuit-go/v2"
)

var (
	ErrVariableInFact = errors.New("parser: a fact cannot contain any variables")
	ErrVariableInSet  = errors.New("parser: a set cannot contain any variables")
)

var BiscuitLexerRules = []lexer.SimpleRule{
	{Name: "Keyword", Pattern: `check if|allow if|deny if`},
	{Name: "Function", Pattern: `prefix|suffix|matches|length|contains`},
	{Name: "Hex", Pattern: `hex:([0-9a-fA-F]{2})*`},
	{Name: "Dot", Pattern: `\.`},
	{Name: "Arrow", Pattern: `<-`},
	{Name: "Or", Pattern: `\|\|`},
	{Name: "And", Pattern: `&&`},
	{Name: "Operator", Pattern: `==|>=|<=|>|<|\+|-|\*`},
	{Name: "Comment", Pattern: `//[^\n]*`},
	{Name: "String", Pattern: `\"[^\"]*\"`},
	{Name: "Variable", Pattern: `\$[a-zA-Z0-9_:]+`},
	{Name: "Parameter", Pattern: `\{[a-zA-Z0-9_:]+\}`},
	{Name: "DateTime", Pattern: `\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?(Z|([-+]\d\d:\d\d))?`},
	{Name: "Int", Pattern: `[0-9]+`},
	{Name: "Bool", Pattern: `true|false`},
	{Name: "Ident", Pattern: `[a-z][a-zA-Z0-9_:]*`},
	{Name: "Whitespace", Pattern: `[ \t]+`},
	{Name: "EOL", Pattern: `[\n\r]+`},
	{Name: "Punct", Pattern: `[-[!@%^&#$*()+_={}\|:;"'<,>.?/]|]`},
}

var DefaultParserOptions = []participle.Option{
	participle.Lexer(lexer.MustSimple(BiscuitLexerRules)),
	participle.UseLookahead(1),
	participle.Elide("Whitespace", "EOL"),
	participle.Unquote("String"),
}

type Parser interface {
	Fact(fact string, parameters ParametersMap) (biscuit.Fact, error)
	Rule(rule string, parameters ParametersMap) (biscuit.Rule, error)
	Check(check string, parameters ParametersMap) (biscuit.Check, error)
	Policy(policy string, parameters ParametersMap) (biscuit.Policy, error)
	Block(block string, parameters ParametersMap) (biscuit.ParsedBlock, error)
	Authorizer(authorizer string, parameters ParametersMap) (biscuit.ParsedAuthorizer, error)

	Must() MustParser
}

type MustParser interface {
	Fact(fact string, parameters ParametersMap) biscuit.Fact
	Rule(rule string, parameters ParametersMap) biscuit.Rule
	Check(check string, parameters ParametersMap) biscuit.Check
	Policy(policy string, parameters ParametersMap) biscuit.Policy
	Block(block string, parameters ParametersMap) biscuit.ParsedBlock
	Authorizer(authorizer string, parameters ParametersMap) biscuit.ParsedAuthorizer
}

type parser struct {
	factParser       *participle.Parser[Predicate]
	ruleParser       *participle.Parser[Rule]
	checkParser      *participle.Parser[Check]
	policyParser     *participle.Parser[Policy]
	blockParser      *participle.Parser[Block]
	authorizerParser *participle.Parser[Authorizer]
}

var _ Parser = (*parser)(nil)

type mustParser struct {
	parser Parser
}

var _ MustParser = (*mustParser)(nil)

func New() Parser {
	return &parser{
		factParser:       participle.MustBuild[Predicate](DefaultParserOptions...),
		ruleParser:       participle.MustBuild[Rule](DefaultParserOptions...),
		checkParser:      participle.MustBuild[Check](DefaultParserOptions...),
		policyParser:     participle.MustBuild[Policy](DefaultParserOptions...),
		blockParser:      participle.MustBuild[Block](DefaultParserOptions...),
		authorizerParser: participle.MustBuild[Authorizer](DefaultParserOptions...),
	}
}

func (p *parser) Fact(fact string, parameters ParametersMap) (biscuit.Fact, error) {
	parsed, err := p.factParser.ParseString("fact", fact)
	if err != nil {
		return biscuit.Fact{}, err
	}

	pred, err := parsed.ToBiscuit(parameters)
	if err != nil {
		return biscuit.Fact{}, err
	}

	for _, a := range pred.IDs {
		if a.Type() == biscuit.TermTypeVariable {
			return biscuit.Fact{}, ErrVariableInFact
		}
	}

	return biscuit.Fact{Predicate: *pred}, nil
}

func (p *parser) Rule(rule string, parameters ParametersMap) (biscuit.Rule, error) {
	parsed, err := p.ruleParser.ParseString("rule", rule)
	if err != nil {
		return biscuit.Rule{}, err
	}

	r, err := parsed.ToBiscuit(parameters)
	if err != nil {
		return biscuit.Rule{}, err
	}

	return *r, nil
}

func (p *parser) Check(check string, parameters ParametersMap) (biscuit.Check, error) {
	parsed, err := p.checkParser.ParseString("check", check)
	if err != nil {
		return biscuit.Check{}, err
	}

	queries := make([]biscuit.Rule, len(parsed.Queries))
	for i, q := range parsed.Queries {
		query, err := q.ToBiscuit(parameters)
		if err != nil {
			return biscuit.Check{}, err
		}

		queries[i] = *query
	}

	return biscuit.Check{
		Queries: queries,
	}, nil
}

func (p *parser) Policy(policy string, parameters ParametersMap) (biscuit.Policy, error) {
	parsed, err := p.policyParser.ParseString("policy", policy)
	if err != nil {
		return biscuit.Policy{}, err
	}

	var parsedQueries []*CheckQuery
	var kind biscuit.PolicyKind
	switch {
	case parsed.Allow != nil:
		{
			parsedQueries = parsed.Allow.Queries
			kind = biscuit.PolicyKindAllow
			break
		}
	case parsed.Deny != nil:
		{
			parsedQueries = parsed.Deny.Queries
			kind = biscuit.PolicyKindDeny
			break
		}
	}

	queries := make([]biscuit.Rule, len(parsedQueries))
	for i, q := range parsedQueries {
		query, err := q.ToBiscuit(parameters)
		if err != nil {
			return biscuit.Policy{}, err
		}

		queries[i] = *query
	}

	return biscuit.Policy{
		Kind:    kind,
		Queries: queries,
	}, nil
}

func (p *parser) Block(block string, parameters ParametersMap) (biscuit.ParsedBlock, error) {
	parsed, err := p.blockParser.ParseString("block", block)
	if err != nil {
		return biscuit.ParsedBlock{}, err
	}
	b, err := parsed.ToBiscuit(parameters)

	if err != nil {
		return biscuit.ParsedBlock{}, err
	}
	return *b, nil
}

func (p *parser) Authorizer(authorizer string, parameters ParametersMap) (biscuit.ParsedAuthorizer, error) {
	parsed, err := p.authorizerParser.ParseString("authorizer", authorizer)
	if err != nil {
		return biscuit.ParsedAuthorizer{}, err
	}
	a, err := parsed.ToBiscuit(parameters)

	if err != nil {
		return biscuit.ParsedAuthorizer{}, err
	}
	return *a, nil
}

func (p *parser) Must() MustParser {
	return &mustParser{parser: p}
}

func (m *mustParser) Fact(fact string, parameters ParametersMap) biscuit.Fact {
	f, err := m.parser.Fact(fact, parameters)
	if err != nil {
		panic(err)
	}

	return f
}

func (m *mustParser) Rule(rule string, parameters ParametersMap) biscuit.Rule {
	r, err := m.parser.Rule(rule, parameters)
	if err != nil {
		panic(err)
	}

	return r
}

func (m *mustParser) Check(check string, parameters ParametersMap) biscuit.Check {
	c, err := m.parser.Check(check, parameters)
	if err != nil {
		panic(err)
	}

	return c
}

func (m *mustParser) Policy(policy string, parameters ParametersMap) biscuit.Policy {
	c, err := m.parser.Policy(policy, parameters)
	if err != nil {
		panic(err)
	}

	return c
}

func (m *mustParser) Block(block string, parameters ParametersMap) biscuit.ParsedBlock {
	c, err := m.parser.Block(block, parameters)
	if err != nil {
		panic(err)
	}

	return c
}

func (m *mustParser) Authorizer(authorizer string, parameters ParametersMap) biscuit.ParsedAuthorizer {
	c, err := m.parser.Authorizer(authorizer, parameters)
	if err != nil {
		panic(err)
	}

	return c
}

func FromStringFact(input string) (biscuit.Fact, error) {
	return FromStringFactWithParams(input, nil)
}

func FromStringRule(input string) (biscuit.Rule, error) {
	return FromStringRuleWithParams(input, nil)
}

func FromStringCheck(input string) (biscuit.Check, error) {
	return FromStringCheckWithParams(input, nil)
}

func FromStringPolicy(input string) (biscuit.Policy, error) {
	return FromStringPolicyWithParams(input, nil)
}

func FromStringBlock(input string) (biscuit.ParsedBlock, error) {
	return FromStringBlockWithParams(input, nil)
}

func FromStringAuthorizer(input string) (biscuit.ParsedAuthorizer, error) {
	return FromStringAuthorizerWithParams(input, nil)
}

func FromStringFactWithParams(input string, parameters ParametersMap) (biscuit.Fact, error) {
	p := New()

	return p.Fact(input, parameters)
}

func FromStringRuleWithParams(input string, parameters ParametersMap) (biscuit.Rule, error) {
	p := New()

	return p.Rule(input, parameters)
}

func FromStringCheckWithParams(input string, parameters ParametersMap) (biscuit.Check, error) {
	p := New()

	return p.Check(input, parameters)
}

func FromStringPolicyWithParams(input string, parameters ParametersMap) (biscuit.Policy, error) {
	p := New()

	return p.Policy(input, parameters)
}

func FromStringBlockWithParams(input string, parameters ParametersMap) (biscuit.ParsedBlock, error) {
	p := New()

	return p.Block(input, parameters)
}

func FromStringAuthorizerWithParams(input string, parameters ParametersMap) (biscuit.ParsedAuthorizer, error) {
	p := New()

	return p.Authorizer(input, parameters)
}
