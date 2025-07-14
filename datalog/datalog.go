// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package datalog

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

type TermType byte

const (
	TermTypeVariable TermType = iota
	TermTypeInteger
	TermTypeString
	TermTypeDate
	TermTypeBytes
	TermTypeBool
	TermTypeSet
)

type Term interface {
	Type() TermType
	Equal(Term) bool
	String() string
}

type TermSet []Term

func (TermSet) Type() TermType { return TermTypeSet }
func (s TermSet) Equal(t Term) bool {
	c, ok := t.(TermSet)
	if !ok || len(c) != len(s) {
		return false
	}

	cmap := make(map[Term]struct{}, len(c))
	for _, v := range c {
		cmap[v] = struct{}{}
	}

	for _, id := range s {
		if _, ok := cmap[id]; !ok {
			return false
		}
	}
	return true
}
func (s TermSet) String() string {
	eltStr := make([]string, 0, len(s))
	for _, e := range s {
		eltStr = append(eltStr, e.String())
	}
	sort.Strings(eltStr)
	return fmt.Sprintf("[%s]", strings.Join(eltStr, ", "))
}
func (s TermSet) Intersect(t TermSet) TermSet {
	other := make(map[Term]struct{}, len(t))
	for _, v := range t {
		other[v] = struct{}{}
	}

	result := TermSet{}

	for _, id := range s {
		if _, ok := other[id]; ok {
			result = append(result, id)
		}
	}
	return result
}
func (s TermSet) Union(t TermSet) TermSet {
	this := make(map[Term]struct{}, len(s))
	for _, v := range s {
		this[v] = struct{}{}
	}

	result := TermSet{}
	result = append(result, s...)

	for _, id := range t {
		if _, ok := this[id]; !ok {
			result = append(result, id)
		}
	}

	return result
}

type Variable uint32

func (Variable) Type() TermType      { return TermTypeVariable }
func (v Variable) Equal(t Term) bool { c, ok := t.(Variable); return ok && v == c }
func (v Variable) String() string {
	return fmt.Sprintf("$%d", v)
}

type Integer int64

func (Integer) Type() TermType      { return TermTypeInteger }
func (i Integer) Equal(t Term) bool { c, ok := t.(Integer); return ok && i == c }
func (i Integer) String() string {
	return fmt.Sprintf("%d", i)
}

type String uint64

func (String) Type() TermType      { return TermTypeString }
func (s String) Equal(t Term) bool { c, ok := t.(String); return ok && s == c }
func (s String) String() string {
	return fmt.Sprintf("#%d", s)
}

type Date uint64

func (Date) Type() TermType      { return TermTypeDate }
func (d Date) Equal(t Term) bool { c, ok := t.(Date); return ok && d == c }
func (d Date) String() string {
	return time.Unix(int64(d), 0).UTC().Format(time.RFC3339)
}

type Bytes []byte

func (Bytes) Type() TermType      { return TermTypeBytes }
func (b Bytes) Equal(t Term) bool { c, ok := t.(Bytes); return ok && bytes.Equal(b, c) }
func (b Bytes) String() string {
	return fmt.Sprintf("hex:%s", hex.EncodeToString(b))
}

type Bool bool

func (Bool) Type() TermType      { return TermTypeBool }
func (b Bool) Equal(t Term) bool { c, ok := t.(Bool); return ok && b == c }
func (b Bool) String() string {
	return fmt.Sprintf("%t", b)
}

type Predicate struct {
	Name  String
	Terms []Term
}

func (p Predicate) Equal(p2 Predicate) bool {
	if p.Name != p2.Name || len(p.Terms) != len(p2.Terms) {
		return false
	}
	for i, id := range p.Terms {
		if !id.Equal(p2.Terms[i]) {
			return false
		}
	}

	return true
}

func (p Predicate) Match(p2 Predicate) bool {
	if p.Name != p2.Name || len(p.Terms) != len(p2.Terms) {
		return false
	}
	for i, id := range p.Terms {
		_, v1 := id.(Variable)
		_, v2 := p2.Terms[i].(Variable)
		if v1 || v2 {
			continue
		}
		if !id.Equal(p2.Terms[i]) {
			return false
		}
	}
	return true
}

func (p Predicate) Clone() Predicate {
	res := Predicate{Name: p.Name, Terms: make([]Term, len(p.Terms))}
	copy(res.Terms, p.Terms)
	return res
}

type Fact struct {
	Predicate
}

type Rule struct {
	Head          Predicate
	Body          []Predicate
	Expressions   []Expression
	TrustedScopes []Scope
}

type InvalidRuleError struct {
	Rule            Rule
	MissingVariable Variable
}

func (e InvalidRuleError) Error() string {
	return fmt.Sprintf("datalog: variable %d in head is missing from body and/or constraints", e.MissingVariable)
}

func (r Rule) Apply(ruleOrigin uint64, factsIterator *FactIterator, newFacts *OriginFacts, syms *SymbolTable) error {

	// extract all variables from the rule body
	variables := make(MatchedVariables)
	for _, predicate := range r.Body {
		for _, term := range predicate.Terms {
			v, ok := term.(Variable)
			if !ok {
				continue
			}
			variables[v] = nil
		}
	}

	combinations := combine(variables, r.Body, factsIterator, syms)
	currentRuleOrigin := MakeOrigin([]uint64{ruleOrigin})

	for res := range combinations {

		if res.error != nil {
			return res.error
		}

		valid := true
		for _, e := range r.Expressions {
			res, err := e.Evaluate(res.MatchedVariables, syms)
			if err != nil {
				return err
			}
			if !res.Equal(Bool(true)) {
				valid = false
				break
			}
		}

		if !valid {
			continue
		}

		predicate := r.Head.Clone()
		for i, term := range predicate.Terms {
			k, ok := term.(Variable)
			if !ok {
				continue
			}
			v, ok := res.MatchedVariables[k]
			if !ok {
				return InvalidRuleError{r, k}
			}

			predicate.Terms[i] = *v
		}
		newOrigin := res.Origin.Merge(currentRuleOrigin)
		newFacts.Insert(newOrigin, Fact{predicate})
	}

	return nil
}

type Check struct {
	Queries []Rule
}

type runLimits struct {
	maxFacts      int
	maxIterations int
	maxDuration   time.Duration
}

var defaultRunLimits = runLimits{
	maxFacts:      1000,
	maxIterations: 100,
	maxDuration:   2 * time.Millisecond,
}

var (
	ErrWorldRunLimitMaxFacts      = errors.New("datalog: world runtime limit: too many facts")
	ErrWorldRunLimitMaxIterations = errors.New("datalog: world runtime limit: too many iterations")
	ErrWorldRunLimitTimeout       = errors.New("datalog: world runtime limit: timeout")
)

type WorldOption func(w *World)

func WithMaxFacts(maxFacts int) WorldOption {
	return func(w *World) {
		w.runLimits.maxFacts = maxFacts
	}
}

func WithMaxIterations(maxIterations int) WorldOption {
	return func(w *World) {
		w.runLimits.maxIterations = maxIterations
	}
}

func WithMaxDuration(maxDuration time.Duration) WorldOption {
	return func(w *World) {
		w.runLimits.maxDuration = maxDuration
	}
}

type World struct {
	facts *OriginFacts
	rules OriginRules

	runLimits runLimits
}

func NewWorld(opts ...WorldOption) *World {
	w := &World{
		facts:     &OriginFacts{},
		runLimits: defaultRunLimits,
	}

	for _, opt := range opts {
		opt(w)
	}

	return w
}

func (w *World) AddFact(origin Origin, f Fact) {
	w.facts.Insert(origin, f)
}

func (w *World) Facts() *OriginFacts {
	return w.facts
}

func (w *World) AddRule(ruleOrigin uint64, scopes TrustedOrigin, r Rule) {
	w.rules.Insert(ruleOrigin, scopes, r)
}

func (w *World) ResetRules() {
	w.rules = OriginRules{}
}

func (w *World) Rules() OriginRules {
	return w.rules
}

func (w *World) Run(syms *SymbolTable) error {
	done := make(chan error)
	ctx, cancel := context.WithTimeout(context.Background(), w.runLimits.maxDuration)
	defer cancel()

	go func() {
		for i := 0; i < w.runLimits.maxIterations; i++ {
			select {
			case <-ctx.Done():
				return
			default:
				var newFacts OriginFacts
				for _, o := range w.rules {
					for _, r := range o.Rules {
						select {
						case <-ctx.Done():
							return
						default:
							factsIterator := w.facts.Iterator(o.TrustedOrigin)
							if err := r.Rule.Apply(r.Origin, &factsIterator, &newFacts, syms); err != nil {
								done <- err
								return
							}
						}
					}
				}

				prevCount := w.facts.Len()
				w.facts.Merge(newFacts)
				newCount := w.facts.Len()
				if newCount >= w.runLimits.maxFacts {
					done <- ErrWorldRunLimitMaxFacts
					return
				}

				// last iteration did not generate any new facts, so we can stop here
				if newCount == prevCount {
					done <- nil
					return
				}
			}
		}
		done <- ErrWorldRunLimitMaxIterations
	}()

	select {
	case <-ctx.Done():
		return ErrWorldRunLimitTimeout
	case err := <-done:
		return err
	}
}

func (w *World) QueryRule(ruleOrigin uint64, scopes TrustedOrigin, rule Rule, syms *SymbolTable) *OriginFacts {
	newFacts := &OriginFacts{}
	factsIterator := w.facts.Iterator(scopes)
	rule.Apply(ruleOrigin, &factsIterator, newFacts, syms)
	return newFacts
}

func (w *World) Clone() *World {
	newFacts := new(OriginFacts)
	*newFacts = *w.facts
	newRules := make(OriginRules, len(w.rules))
	copy(newRules, w.rules)
	return &World{
		facts:     newFacts,
		rules:     newRules,
		runLimits: w.runLimits,
	}
}

type MatchedVariables map[Variable]*Term

func (m MatchedVariables) Insert(k Variable, v Term) bool {
	existing := m[k]
	if existing == nil {
		m[k] = &v
		return true
	}
	return v.Equal(*existing)
}

func (m MatchedVariables) Complete() map[Variable]*Term {
	for _, v := range m {
		if v == nil {
			return nil
		}
	}
	return (map[Variable]*Term)(m)
}

func (m MatchedVariables) Clone() MatchedVariables {
	res := make(MatchedVariables, len(m))
	for k, v := range m {
		res[k] = v
	}
	return res
}

func combine(variables MatchedVariables, predicates []Predicate, facts *FactIterator, syms *SymbolTable) <-chan struct {
	Origin
	MatchedVariables
	error
} {
	c := make(chan struct {
		Origin
		MatchedVariables
		error
	})

	go func(c chan struct {
		Origin
		MatchedVariables
		error
	}) {
		defer close(c)

		if len(predicates) == 0 {
			if variables.Complete() != nil {
				c <- struct {
					Origin
					MatchedVariables
					error
				}{[]uint64{}, variables, nil}
			}
			return
		}

		currentFacts := facts.makeIterator()
	Facts:
		for fact := range currentFacts {
			if fact.Match(predicates[0]) {
				vars := variables.Clone()

				for j := 0; j < len(predicates[0].Terms); j++ {
					term := predicates[0].Terms[j]
					k, ok := term.(Variable)
					if !ok {
						continue
					}
					v := fact.Predicate.Terms[j]
					if !vars.Insert(k, v) {
						continue Facts
					}
				}

				if len(predicates) == 1 {
					if vars.Complete() != nil {
						c <- struct {
							Origin
							MatchedVariables
							error
						}{fact.Origin, vars, nil}
					}
				} else {
					currentOrigin := fact.Origin
					for res := range combine(vars, predicates[1:], facts, syms) {
						if res.error != nil {
							c <- struct {
								Origin
								MatchedVariables
								error
							}{nil, nil, res.error}
							return
						}

						newOrigin := currentOrigin.Merge(res.Origin)
						c <- struct {
							Origin
							MatchedVariables
							error
						}{newOrigin, res.MatchedVariables, res.error}
					}
				}
			}
		}
	}(c)
	return c
}
