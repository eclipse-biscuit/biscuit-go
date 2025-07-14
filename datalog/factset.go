// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package datalog

import (
	"math"
	"slices"
)

type SingleOrigin uint64
type Origin []uint64
type TrustedOrigin struct{ Origin }

func MakeOrigin(ids []uint64) Origin {
	slices.Sort(ids)
	return slices.Compact(ids)
}

func AuthorityOrigin() Origin {
	return []uint64{0}
}

func AuthorizerOrigin() Origin {
	return []uint64{math.MaxUint64}
}

func (o Origin) Equal(other Origin) bool {
	return slices.Equal(o, other)
}

func (o Origin) Merge(other Origin) Origin {
	ids := append(o, other...)
	return MakeOrigin(ids)
}

func DefaultTrustedOrigin() TrustedOrigin {
	ids := []uint64{0, math.MaxUint64}
	return TrustedOrigin{Origin: MakeOrigin(ids)}
}

// let authorizer_trusted_origins = TrustedOrigins::from_scopes(
//
//	&authorizer_scopes,
//	&TrustedOrigins::default(),
//	usize::MAX,
//	&public_key_to_block_id,
//
// );
func AuthorizerTrustedOrigins(authorizerScopes []Scope, publicKeyToBlockId map[uint64][]uint64) TrustedOrigin {
	return TrustedOriginsFromScopes(authorizerScopes, DefaultTrustedOrigin(), math.MaxUint64, publicKeyToBlockId)
}

func TrustedOriginsFromScopes(ruleScopes []Scope, defaultOrigins TrustedOrigin, currentBlock uint64, publicKeyToBlockId map[uint64][]uint64) TrustedOrigin {
	if len(ruleScopes) == 0 {
		origins := defaultOrigins.Origin
		origins = append(origins, currentBlock)
		origins = append(origins, math.MaxUint64)
		return TrustedOrigin{Origin: origins}
	}

	origins := Origin{}
	origins = append(origins, currentBlock)
	origins = append(origins, math.MaxUint64)

	for _, scope := range ruleScopes {
		switch scope.Type() {
		case ScopeTypeAuthority:
			origins = append(origins, 0)
		case ScopeTypePrevious:
			if currentBlock != math.MaxUint64 {
				origins = append(origins, 0, currentBlock+1)
			}
		case ScopeTypePublicKey:
			if blockIds, ok := publicKeyToBlockId[scope.(PublicKeyScope).ID]; ok {
				origins = append(origins, blockIds...)
			}
		}
	}

	return TrustedOrigin{Origin: origins}
}

func (o TrustedOrigin) Equal(other TrustedOrigin) bool {
	return slices.Equal(o.Origin, other.Origin)
}

func (o TrustedOrigin) Contains(other Origin) bool {
	for _, v := range other {
		if !slices.Contains(o.Origin, v) {
			return false
		}
	}
	return true
}

type OriginWithFacts struct {
	Origin Origin
	Facts  *FactSet
}

type OriginFacts []OriginWithFacts

func (s *OriginFacts) Insert(origin Origin, f Fact) bool {
	for _, v := range *s {
		if v.Origin.Equal(origin) {
			return v.Facts.Insert(f)
		}
	}

	(*s) = append(*s, OriginWithFacts{Origin: origin, Facts: &FactSet{Facts: []Fact{f}}})
	return true

}

func (s *OriginFacts) InsertAll(origin Origin, facts []Fact) {
	for _, v := range *s {
		if v.Origin.Equal(origin) {
			v.Facts.InsertAll(facts)
			return
		}
	}

	(*s) = append(*s, OriginWithFacts{Origin: origin, Facts: &FactSet{Facts: facts}})
}

func (s *OriginFacts) Merge(other OriginFacts) {
	for _, factSet := range other {

		found := false
		for _, v := range *s {
			if v.Origin.Equal(factSet.Origin) {
				v.Facts.InsertAll(factSet.Facts.Facts)
				found = true
			}
		}

		if !found {
			(*s) = append(*s, factSet)
		}

	}
}

func (s *OriginWithFacts) Merge(other OriginWithFacts) {
	for _, f := range other.Facts.Facts {
		s.Facts.Insert(f)
	}
}

func (s *OriginFacts) Equal(x *OriginFacts) bool {
	if len(*s) != len(*x) {
		return false
	}

	for _, facts := range *x {
		found := false
		for _, v := range *s {
			if v.Origin.Equal(facts.Origin) {
				if !v.Facts.Equal(facts.Facts) {
					return false
				}
				found = true
				break
			}
		}

		if !found {
			return false
		}
	}

	return true
}

func (s *OriginFacts) Len() int {
	count := 0
	for _, v := range *s {
		count += len(v.Facts.Facts)
	}
	return count
}

func (s *OriginFacts) Iterator(o TrustedOrigin) FactIterator {
	return FactIterator{
		origin: o,
		facts:  s,
	}
}

type FactIterator struct {
	origin TrustedOrigin
	facts  *OriginFacts
}

func (f *FactIterator) makeIterator() <-chan struct {
	Origin
	Fact
} {
	c := make(chan struct {
		Origin
		Fact
	})

	go func(c chan struct {
		Origin
		Fact
	}) {
		defer close(c)

		for _, v := range *f.facts {
			if f.origin.Contains(v.Origin) {
				for _, fact := range v.Facts.Facts {
					c <- struct {
						Origin
						Fact
					}{v.Origin, fact}
				}
			}
		}
	}(c)
	return c
}

type FactSet struct {
	Facts []Fact
}

func (s *FactSet) Insert(f Fact) bool {
	for _, v := range s.Facts {
		if v.Equal(f.Predicate) {
			return false
		}
	}

	s.Facts = append(s.Facts, f)
	return true
}

func (s *FactSet) InsertAll(facts []Fact) {
	for _, f := range facts {
		s.Insert(f)
	}
}

func (s *FactSet) Equal(x *FactSet) bool {
	if len(s.Facts) != len(x.Facts) {
		return false
	}
	for _, f1 := range x.Facts {
		found := false
		for _, f2 := range s.Facts {
			if f1.Predicate.Equal(f2.Predicate) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

type OriginRules []TrustedOriginWithRules

type TrustedOriginWithRules struct {
	TrustedOrigin TrustedOrigin
	Rules         []OriginWithRule
}

type OriginWithRule struct {
	Origin uint64
	Rule   Rule
}

func (s *OriginRules) Insert(ruleOrigin uint64, scopes TrustedOrigin, r Rule) {
	for _, v := range *s {
		if v.TrustedOrigin.Equal(scopes) {
			v.Rules = append(v.Rules, OriginWithRule{Origin: ruleOrigin, Rule: r})
		}
	}

	(*s) = append(*s, TrustedOriginWithRules{TrustedOrigin: scopes, Rules: []OriginWithRule{{Origin: ruleOrigin, Rule: r}}})
}

func (s *OriginRules) InsertAll(ruleOrigin uint64, scopes TrustedOrigin, rules []Rule) {
	for _, v := range *s {
		if v.TrustedOrigin.Equal(scopes) {
			for _, r := range rules {
				v.Rules = append(v.Rules, OriginWithRule{Origin: ruleOrigin, Rule: r})
			}
			return
		}
	}

	oRules := make([]OriginWithRule, len(rules))
	for i, r := range rules {
		oRules[i] = OriginWithRule{Origin: ruleOrigin, Rule: r}
	}
	(*s) = append(*s, TrustedOriginWithRules{TrustedOrigin: scopes, Rules: oRules})
}

func (s *OriginRules) Merge(other OriginRules) {
	for _, v := range other {

		found := false
		for _, v := range *s {
			if v.TrustedOrigin.Equal(v.TrustedOrigin) {
				v.Rules = append(v.Rules, v.Rules...)
				found = true
			}
		}

		if !found {
			(*s) = append(*s, v)
		}

	}
}

func (s *TrustedOriginWithRules) Merge(other TrustedOriginWithRules) {
	s.Rules = append(s.Rules, other.Rules...)
}
