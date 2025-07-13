// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package biscuit

import (
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/biscuit-auth/biscuit-go/v2/datalog"
)

var (
	ErrMissingSymbols   = errors.New("biscuit: missing symbols")
	ErrPolicyDenied     = errors.New("biscuit: denied by policy")
	ErrNoMatchingPolicy = errors.New("biscuit: denied by no matching policies")
)

type Authorizer interface {
	AddAuthorizer(a ParsedAuthorizer)
	AddBlock(b ParsedBlock)
	AddFact(fact Fact)
	AddRule(rule Rule)
	AddCheck(check Check)
	AddPolicy(policy Policy)
	Authorize() error
	Query(rule Rule) (FactSet, error)
	Biscuit() *Biscuit
	Reset()
	PrintWorld() string
	// LoadPolicies([]byte) error
	// SerializePolicies() ([]byte, error)
}

type authorizer struct {
	biscuit            *Biscuit
	baseWorld          *datalog.World
	world              *datalog.World
	baseSymbols        *datalog.SymbolTable
	symbols            *datalog.SymbolTable
	block_worlds       []*datalog.World
	scopes             []datalog.Scope
	publicKeyToBlockId map[uint64][]uint64

	checks   []Check
	policies []Policy

	dirty bool
}

var _ Authorizer = (*authorizer)(nil)

type AuthorizerOption func(w *authorizer)

func WithWorldOptions(opts ...datalog.WorldOption) AuthorizerOption {
	return func(a *authorizer) {
		a.baseWorld = datalog.NewWorld(opts...)
	}
}

func NewVerifier(b *Biscuit, opts ...AuthorizerOption) (Authorizer, error) {
	a := &authorizer{
		biscuit:      b,
		baseWorld:    datalog.NewWorld(),
		baseSymbols:  defaultSymbolTable.Clone(),
		checks:       []Check{},
		policies:     []Policy{},
		block_worlds: []*datalog.World{},
	}

	for _, opt := range opts {
		opt(a)
	}

	a.world = a.baseWorld.Clone()
	a.symbols = a.baseSymbols.Clone()

	return a, nil
}

func (v *authorizer) AddAuthorizer(a ParsedAuthorizer) {
	v.AddBlock(a.Block)
	for _, p := range a.Policies {
		v.AddPolicy(p)
	}
}

func (v *authorizer) AddBlock(block ParsedBlock) {
	for _, f := range block.Facts {
		v.AddFact(f)
	}
	for _, r := range block.Rules {
		v.AddRule(r)
	}
	for _, c := range block.Checks {
		v.AddCheck(c)
	}
}

func (v *authorizer) AddFact(fact Fact) {
	v.world.AddFact(datalog.AuthorizerOrigin(), fact.convert(v.symbols))
}

func (v *authorizer) AddRule(rule Rule) {
	authorizerTrustedOrigins := datalog.AuthorizerTrustedOrigins(v.scopes, v.publicKeyToBlockId)
	ruleTrustedOrigins := datalog.TrustedOriginsFromScopes(rule.Scopes, authorizerTrustedOrigins, math.MaxUint64, v.publicKeyToBlockId)
	v.world.AddRule(math.MaxUint64, ruleTrustedOrigins, rule.convert(v.symbols))
}

func (v *authorizer) AddCheck(check Check) {
	v.checks = append(v.checks, check)
}

func (v *authorizer) AddPolicy(policy Policy) {
	v.policies = append(v.policies, policy)
}

func (v *authorizer) Authorize() error {
	// if we load facts from the verifier before
	// the token's fact and rules, we might get inconsistent symbols
	// token ements should first be converted to builder elements
	// with the token's symbol table, then converted back
	// with the verifier's symbol table
	authorityOrigin := datalog.AuthorityOrigin()
	authorizerTrustedOrigins := datalog.AuthorizerTrustedOrigins(v.scopes, v.publicKeyToBlockId)

	for _, fact := range v.biscuit.authority.facts {
		f, err := fromDatalogFact(v.biscuit.symbols, fact)
		if err != nil {
			return fmt.Errorf("biscuit: verification failed: %s", err)
		}
		v.world.AddFact(authorityOrigin, f.convert(v.symbols))
	}

	authorityBlockTrustedOrigins := datalog.TrustedOriginsFromScopes(v.biscuit.authority.scopes, datalog.DefaultTrustedOrigin(), 0, v.publicKeyToBlockId)
	for _, rule := range v.biscuit.authority.rules {
		r, err := fromDatalogRule(v.biscuit.symbols, rule)
		if err != nil {
			return fmt.Errorf("biscuit: verification failed: %s", err)
		}
		ruleTrustedOrigins := datalog.TrustedOriginsFromScopes(r.Scopes, authorityBlockTrustedOrigins, 0, v.publicKeyToBlockId)

		v.world.AddRule(0, ruleTrustedOrigins, r.convert(v.symbols))
	}

	for i, block := range v.biscuit.blocks {
		blockTrustedOrigins := datalog.TrustedOriginsFromScopes(block.scopes, datalog.DefaultTrustedOrigin(), uint64(i+1), v.publicKeyToBlockId)
		blockOrigin := datalog.MakeOrigin([]uint64{uint64(i + 1)})
		for _, fact := range block.facts {
			f, err := fromDatalogFact(v.biscuit.symbols, fact)
			if err != nil {
				return fmt.Errorf("biscuit: verification failed: %s", err)
			}
			v.world.AddFact(blockOrigin, f.convert(v.symbols))
		}

		for _, rule := range block.rules {
			r, err := fromDatalogRule(v.biscuit.symbols, rule)
			if err != nil {
				return fmt.Errorf("biscuit: verification failed: %s", err)
			}
			ruleTrustedOrigins := datalog.TrustedOriginsFromScopes(r.Scopes, blockTrustedOrigins, uint64(i+1), v.publicKeyToBlockId)
			v.world.AddRule(uint64(i+1), ruleTrustedOrigins, r.convert(v.symbols))
		}
	}

	if err := v.world.Run(v.symbols); err != nil {
		return err
	}
	v.dirty = true

	var errs []error

	for i, check := range v.checks {
		c := check.convert(v.symbols)
		successful := false
		for _, query := range c.Queries {
			res := v.world.QueryRule(math.MaxUint64, authorizerTrustedOrigins, query, v.symbols)
			if len(*res) != 0 {
				successful = true
				break
			}
		}
		if !successful {
			debug := datalog.SymbolDebugger{
				SymbolTable: v.symbols,
			}
			errs = append(errs, fmt.Errorf("failed to verify check #%d: %s", i, debug.Check(c)))
		}
	}

	for i, check := range v.biscuit.authority.checks {
		ch, err := fromDatalogCheck(v.biscuit.symbols, check)
		if err != nil {
			return fmt.Errorf("biscuit: verification failed: %s", err)
		}
		c := ch.convert(v.symbols)

		successful := false
		for _, query := range c.Queries {
			res := v.world.QueryRule(0, authorityBlockTrustedOrigins, query, v.symbols)
			if len(*res) != 0 {
				successful = true
				break
			}
		}
		if !successful {
			debug := datalog.SymbolDebugger{
				SymbolTable: v.symbols,
			}
			errs = append(errs, fmt.Errorf("failed to verify block 0 check #%d: %s", i, debug.Check(c)))
		}
	}

	policyMatched := false
	policyResult := ErrPolicyDenied
	for _, policy := range v.policies {
		if policyMatched {
			break
		}
		for _, query := range policy.Queries {
			res := v.world.QueryRule(math.MaxUint64, authorizerTrustedOrigins, query.convert(v.symbols), v.symbols)
			if len(*res) != 0 {
				switch policy.Kind {
				case PolicyKindAllow:
					policyResult = nil
					policyMatched = true
				case PolicyKindDeny:
					policyResult = ErrPolicyDenied
					policyMatched = true
				}
				break
			}
		}
	}

	for i, block := range v.biscuit.blocks {
		blockTrustedOrigins := datalog.TrustedOriginsFromScopes(block.scopes, datalog.DefaultTrustedOrigin(), uint64(i+1), v.publicKeyToBlockId)

		for j, check := range block.checks {
			ch, err := fromDatalogCheck(v.biscuit.symbols, check)
			if err != nil {
				return fmt.Errorf("biscuit: verification failed: %s", err)
			}
			c := ch.convert(v.symbols)

			successful := false
			for _, query := range c.Queries {
				res := v.world.QueryRule(uint64(i+1), blockTrustedOrigins, query, v.symbols)

				if len(*res) != 0 {
					successful = true
					break
				}
			}
			if !successful {
				debug := datalog.SymbolDebugger{
					SymbolTable: v.symbols,
				}
				errs = append(errs, fmt.Errorf("failed to verify block #%d check #%d: %s", i+1, j, debug.Check(c)))
			}
		}
	}

	if len(errs) > 0 {
		errMsg := make([]string, len(errs))
		for i, e := range errs {
			errMsg[i] = e.Error()
		}

		return fmt.Errorf("biscuit: verification failed: %s", strings.Join(errMsg, ", "))
	}

	v.baseWorld = v.world.Clone()
	v.baseSymbols = v.symbols.Clone()

	if policyMatched {
		return policyResult
	} else {
		return ErrNoMatchingPolicy
	}
}

func (v *authorizer) Query(rule Rule) (FactSet, error) {
	if err := v.world.Run(v.symbols); err != nil {
		return nil, err
	}

	authorizerTrustedOrigins := datalog.AuthorizerTrustedOrigins(v.scopes, v.publicKeyToBlockId)
	factSet := v.world.QueryRule(math.MaxUint64, authorizerTrustedOrigins, rule.convert(v.symbols), v.symbols)

	result := make([]Fact, 0, len(*factSet))
	for _, facts := range *factSet {
		for _, fact := range facts.Facts.Facts {
			f, err := fromDatalogFact(v.symbols, fact)
			if err != nil {
				return nil, err
			}

			result = append(result, *f)
		}
	}

	return result, nil
}

func (v *authorizer) Biscuit() *Biscuit {
	return v.biscuit
}

// Returns the content of the Datalog environment
// This will be empty until the call to Authorize(), where
// facts, rules and checks will be evaluated
func (v *authorizer) PrintWorld() string {
	debug := datalog.SymbolDebugger{
		SymbolTable: v.symbols,
	}

	return debug.World(v.world)
}

func (v *authorizer) Reset() {
	v.world = v.baseWorld.Clone()
	v.symbols = v.baseSymbols.Clone()
	v.checks = []Check{}
	v.policies = []Policy{}
	v.dirty = false
}

// func (v *authorizer) LoadPolicies(authorizerPolicies []byte) error {
// 	pbPolicies := &pb.AuthorizerPolicies{}
// 	if err := proto.Unmarshal(authorizerPolicies, pbPolicies); err != nil {
// 		return fmt.Errorf("verifier: failed to load policies: %w", err)
// 	}

// 	switch pbPolicies.GetVersion() {
// 	case 3:
// 		return v.loadPolicies(pbPolicies)
// 	default:
// 		return fmt.Errorf("verifier: unsupported policies version %d", pbPolicies.GetVersion())
// 	}
// }

// func (v *authorizer) loadPolicies(pbPolicies *pb.AuthorizerPolicies) error {
// 	policySymbolTable := datalog.SymbolTable{
// 		Symbols: pbPolicies.Symbols,
// 	}
// 	v.symbols = v.baseSymbols.Clone()
// 	v.symbols.Extend(&policySymbolTable)

// 	authorizerOrigin := datalog.AuthorizerOrigin()
// 	for _, pbFact := range pbPolicies.Facts {
// 		fact, err := protoFactToTokenFact(pbFact)
// 		if err != nil {
// 			return fmt.Errorf("verifier: load policies v1: failed to convert datalog fact: %w", err)
// 		}
// 		v.world.AddFact(authorizerOrigin, *fact)
// 	}

// 	for _, pbRule := range pbPolicies.Rules {
// 		rule, err := protoRuleToTokenRule(pbRule)
// 		if err != nil {
// 			return fmt.Errorf("verifier: load policies v1: failed to convert datalog rule: %w", err)
// 		}
// 		v.world.AddRule(math.MaxUint64, *rule)
// 	}

// 	v.checks = make([]Check, len(pbPolicies.Checks))
// 	for i, pbCheck := range pbPolicies.Checks {
// 		dlCheck, err := protoCheckToTokenCheck(pbCheck)
// 		if err != nil {
// 			return fmt.Errorf("verifier: load policies v1: failed to convert datalog check: %w", err)
// 		}
// 		check, err := fromDatalogCheck(v.symbols, *dlCheck)
// 		if err != nil {
// 			return fmt.Errorf("verifier: load policies v1: failed to convert check: %w", err)
// 		}
// 		v.checks[i] = *check
// 	}

// 	v.policies = make([]Policy, len(pbPolicies.Policies))
// 	for i, pbPolicy := range pbPolicies.Policies {
// 		policy := Policy{}
// 		switch *pbPolicy.Kind {
// 		case pb.Policy_Allow:
// 			policy.Kind = PolicyKindAllow
// 		case pb.Policy_Deny:
// 			policy.Kind = PolicyKindDeny
// 		default:
// 			return fmt.Errorf("verifier: load policies v1: unsupported proto policy kind %v", pbPolicy.Kind)
// 		}

// 		policy.Queries = make([]Rule, len(pbPolicy.Queries))
// 		for j, pbRule := range pbPolicy.Queries {
// 			dlRule, err := protoRuleToTokenRule(pbRule)
// 			if err != nil {
// 				return fmt.Errorf("verifier: load policies v1: failed to convert datalog policy rule: %w", err)
// 			}

// 			rule, err := fromDatalogRule(v.symbols, *dlRule)
// 			if err != nil {
// 				return fmt.Errorf("verifier: load policies v1: failed to convert policy rule: %w", err)
// 			}
// 			policy.Queries[j] = *rule
// 		}
// 		v.policies[i] = policy
// 	}

// 	return nil
// }

// func (v *authorizer) SerializePolicies() ([]byte, error) {
// 	if v.dirty {
// 		return nil, errors.New("verifier: can't serialize after world has been run")
// 	}

// 	protoFacts := make([]*pb.Fact, len(*v.world.Facts()))
// 	for i, fact := range *v.world.Facts() {
// 		protoFact, err := tokenFactToProtoFact(fact)
// 		if err != nil {
// 			return nil, fmt.Errorf("verifier: failed to convert fact: %w", err)
// 		}
// 		protoFacts[i] = protoFact
// 	}

// 	protoRules := make([]*pb.Rule, len(v.world.Rules()))
// 	for i, rule := range v.world.Rules() {
// 		protoRule, err := tokenRuleToProtoRule(rule)
// 		if err != nil {
// 			return nil, fmt.Errorf("verifier: failed to convert rule: %w", err)
// 		}
// 		protoRules[i] = protoRule
// 	}

// 	protoChecks := make([]*pb.Check, len(v.checks))
// 	for i, check := range v.checks {
// 		protoCheck, err := tokenCheckToProtoCheck(check.convert(v.symbols))
// 		if err != nil {
// 			return nil, fmt.Errorf("verifier: failed to convert check: %w", err)
// 		}
// 		protoChecks[i] = protoCheck
// 	}

// 	protoPolicies := make([]*pb.Policy, len(v.policies))
// 	for i, policy := range v.policies {
// 		protoPolicy := &pb.Policy{}
// 		switch policy.Kind {
// 		case PolicyKindAllow:
// 			kind := pb.Policy_Allow
// 			protoPolicy.Kind = &kind
// 		case PolicyKindDeny:
// 			kind := pb.Policy_Deny
// 			protoPolicy.Kind = &kind
// 		default:
// 			return nil, fmt.Errorf("verifier: unsupported policy kind %v", policy.Kind)
// 		}

// 		protoPolicy.Queries = make([]*pb.Rule, len(policy.Queries))
// 		for j, rule := range policy.Queries {
// 			protoRule, err := tokenRuleToProtoRule(rule.convert(v.symbols))
// 			if err != nil {
// 				return nil, fmt.Errorf("verifier: failed to convert policy rule: %w", err)
// 			}
// 			protoPolicy.Queries[j] = protoRule
// 		}

// 		protoPolicies[i] = protoPolicy
// 	}

// 	version := MaxSchemaVersion
// 	return proto.Marshal(&pb.AuthorizerPolicies{
// 		Symbols:  v.symbols.Clone().Symbols,
// 		Version:  proto.Uint32(version),
// 		Facts:    protoFacts,
// 		Rules:    protoRules,
// 		Checks:   protoChecks,
// 		Policies: protoPolicies,
// 	})
// }
