package biscuit

import (
	"fmt"
	"iter"
	"slices"

	"github.com/eclipse-biscuit/biscuit-go/v2/datalog"
	"github.com/eclipse-biscuit/biscuit-go/v2/internal/set"
)

// InspectAuthorizer is intended to only be used while testing to visit the internal state of the [[Authorizer]].
func InspectAuthorizer(a Authorizer, f func(inspector AuthorizerInspector)) error {
	if inspectableAuthorizer, canInspect := a.(*authorizer); canInspect {
		f(&authorizerInspector{inspectableAuthorizer})
		return nil
	}

	return fmt.Errorf("authorizer is not inspectable")
}

type AuthorizerInspector interface {
	Authorizer

	Facts() iter.Seq2[[]uint64, []Fact]
	Rules() iter.Seq2[uint64, []Rule]
	Checks() iter.Seq2[uint64, []Check]
	Policies() iter.Seq[Policy]
	Symbols() iter.Seq[string]
	PublicKeys() iter.Seq[datalog.PublicKey]
}

type authorizerInspector struct {
	*authorizer
}

func (v *authorizerInspector) Facts() iter.Seq2[[]uint64, []Fact] {
	return func(yield func([]uint64, []Fact) bool) {
		for origin, facts := range v.world.Facts.IterSorted() {
			blockIDs := slices.Collect(origin.BlockIDs())

			biscuitFacts := make([]Fact, 0, facts.Size())
			for _, dlFact := range set.Sorted(facts.Iter()) {
				biscuitFact, err := fromDatalogFact(v.symbols, dlFact)
				if err != nil {
					continue
				}
				biscuitFacts = append(biscuitFacts, *biscuitFact)
			}
			if len(biscuitFacts) > 0 {
				if !yield(blockIDs, biscuitFacts) {
					return
				}
			}
		}
	}
}

func (v *authorizerInspector) Rules() iter.Seq2[uint64, []Rule] {
	return func(yield func(uint64, []Rule) bool) {
		for blockID, rules := range v.world.Rules.RulesByBlockID() {
			biscuitRules := make([]Rule, 0, len(rules))
			for _, dlRule := range rules {
				biscuitRule, err := fromDatalogRule(v.symbols, v.publicKeys, dlRule)
				if err != nil {
					continue
				}
				biscuitRules = append(biscuitRules, *biscuitRule)
			}

			if len(biscuitRules) > 0 {
				if !yield(uint64(blockID), biscuitRules) {
					return
				}
			}
		}
	}
}

func (v *authorizerInspector) Checks() iter.Seq2[uint64, []Check] {
	return func(yield func(uint64, []Check) bool) {
		// Yield authorizer checks
		if len(v.authorizerChecks) > 0 {
			authorizerBiscuitChecks := make([]Check, 0, len(v.authorizerChecks))
			for _, check := range v.authorizerChecks {
				biscuitCheck, err := fromDatalogCheck(v.symbols, v.publicKeys, check)
				if err != nil {
					continue
				}
				authorizerBiscuitChecks = append(authorizerBiscuitChecks, *biscuitCheck)
			}

			// Sort the checks
			slices.SortFunc(authorizerBiscuitChecks, func(a, b Check) int { return a.Compare(b) })

			if len(authorizerBiscuitChecks) > 0 {
				if !yield(datalog.AuthorizerBlockID, authorizerBiscuitChecks) {
					return
				}
			}
		}

		// Yield biscuit checks
		for blockID, dlChecks := range v.biscuitChecks {
			biscuitChecks := make([]Check, 0, len(dlChecks))
			for _, check := range dlChecks {
				biscuitCheck, err := fromDatalogCheck(v.symbols, v.publicKeys, check)
				if err != nil {
					continue
				}
				biscuitChecks = append(biscuitChecks, *biscuitCheck)
			}

			// Sort the checks
			slices.SortFunc(biscuitChecks, func(a, b Check) int { return a.Compare(b) })

			if len(biscuitChecks) > 0 {
				if !yield(uint64(blockID), biscuitChecks) {
					return
				}
			}
		}
	}
}

func (v *authorizerInspector) Policies() iter.Seq[Policy] {
	return func(yield func(Policy) bool) {
		for _, policy := range v.authorizerPolicies {
			if !yield(policy) {
				return
			}
		}
	}
}

func (v *authorizerInspector) Symbols() iter.Seq[string] {
	return func(yield func(string) bool) {
		for _, sym := range *v.symbols {
			if !yield(sym) {
				return
			}
		}
	}
}

func (v *authorizerInspector) PublicKeys() iter.Seq[datalog.PublicKey] {
	return func(yield func(datalog.PublicKey) bool) {
		for _, pk := range *v.publicKeys {
			if !yield(pk) {
				return
			}
		}
	}
}
