// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package datalog

import (
	"bytes"
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

// Term is a value in a predicate. Implementations are value types and
// Equal compares by value, using a type assertion on the concrete type.
// Do not store a pointer to a term (such as *Bytes) in a Term: the
// pointer would still satisfy the interface, but Equal would not match it.
type Term interface {
	Type() TermType
	Equal(Term) bool
	String() string
}

// Keep the value types implementing Term; a pointer receiver on any of them would break Equal.
var (
	_ Term = Variable(0)
	_ Term = Integer(0)
	_ Term = String(0)
	_ Term = Date(0)
	_ Term = Bytes(nil)
	_ Term = Bool(false)
	_ Term = Set(nil)
)

type Set []Term

func (Set) Type() TermType { return TermTypeSet }

// Bytes is a slice and cannot be a map key, so look up elements with Equal.
func (s Set) contains(t Term) bool {
	for _, e := range s {
		if e.Equal(t) {
			return true
		}
	}
	return false
}

func (s Set) Equal(t Term) bool {
	c, ok := t.(Set)
	if !ok || len(c) != len(s) {
		return false
	}

	// Both directions: a duplicate on one side could otherwise hide a missing element.
	for _, e := range s {
		if !c.contains(e) {
			return false
		}
	}
	for _, e := range c {
		if !s.contains(e) {
			return false
		}
	}
	return true
}
func (s Set) String() string {
	eltStr := make([]string, 0, len(s))
	for _, e := range s {
		eltStr = append(eltStr, e.String())
	}
	sort.Strings(eltStr)
	return fmt.Sprintf("[%s]", strings.Join(eltStr, ", "))
}
func (s Set) Intersect(t Set) Set {
	result := Set{}

	for _, e := range s {
		if t.contains(e) {
			result = append(result, e)
		}
	}
	return result
}
func (s Set) Union(t Set) Set {
	result := Set{}
	result = append(result, s...)

	for _, e := range t {
		if !s.contains(e) {
			result = append(result, e)
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
	Head        Predicate
	Body        []Predicate
	Expressions []Expression
}

type InvalidRuleError struct {
	Rule            Rule
	MissingVariable Variable
}

func (e InvalidRuleError) Error() string {
	return fmt.Sprintf("datalog: variable %d in head is missing from body and/or constraints", e.MissingVariable)
}

func (r Rule) Apply(facts *FactSet, newFacts *FactSet, syms *SymbolTable) error {
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

	combinations, err := combine(variables, r.Body, r.Expressions, facts, syms)
	if err != nil {
		return err
	}

	for _, res := range combinations {
		predicate := r.Head.Clone()
		for i, term := range predicate.Terms {
			k, ok := term.(Variable)
			if !ok {
				continue
			}
			v, ok := res[k]
			if !ok {
				return InvalidRuleError{r, k}
			}

			predicate.Terms[i] = *v
		}
		newFacts.Insert(Fact{predicate})
	}

	return nil
}

type Check struct {
	Queries []Rule
}

type FactSet []Fact

func (s *FactSet) Insert(f Fact) bool {
	for _, v := range *s {
		if v.Equal(f.Predicate) {
			return false
		}
	}
	*s = append(*s, f)
	return true
}

func (s *FactSet) InsertAll(facts []Fact) {
	for _, f := range facts {
		s.Insert(f)
	}
}

func (s *FactSet) Equal(x *FactSet) bool {
	if len(*s) != len(*x) {
		return false
	}
	for _, f1 := range *x {
		found := false
		for _, f2 := range *s {
			if f1.Equal(f2.Predicate) {
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
	facts *FactSet
	rules []Rule

	runLimits runLimits
}

func NewWorld(opts ...WorldOption) *World {
	w := &World{
		facts:     &FactSet{},
		runLimits: defaultRunLimits,
	}

	for _, opt := range opts {
		opt(w)
	}

	return w
}

func (w *World) AddFact(f Fact) {
	w.facts.Insert(f)
}

func (w *World) Facts() *FactSet {
	return w.facts
}

func (w *World) AddRule(r Rule) {
	w.rules = append(w.rules, r)
}

func (w *World) ResetRules() {
	w.rules = make([]Rule, 0)
}

func (w *World) Rules() []Rule {
	return w.rules
}

func (w *World) Run(syms *SymbolTable) error {
	deadline := time.Now().Add(w.runLimits.maxDuration)
	for i := 0; i < w.runLimits.maxIterations; i++ {
		var newFacts FactSet
		for _, r := range w.rules {
			if time.Now().After(deadline) {
				return ErrWorldRunLimitTimeout
			}
			if err := r.Apply(w.facts, &newFacts, syms); err != nil {
				return err
			}
		}

		prevCount := len(*w.facts)
		w.facts.InsertAll([]Fact(newFacts))

		newCount := len(*w.facts)
		if newCount >= w.runLimits.maxFacts {
			return ErrWorldRunLimitMaxFacts
		}

		// last iteration did not generate any new facts, so we can stop here
		if newCount == prevCount {
			return nil
		}
	}
	return ErrWorldRunLimitMaxIterations
}

func (w *World) Query(pred Predicate) *FactSet {
	res := &FactSet{}
	for _, f := range *w.facts {
		if f.Name != pred.Name {
			continue
		}

		// if the predicate has a different number of IDs
		// the fact must not match
		if len(f.Terms) != len(pred.Terms) {
			continue
		}

		matches := true
		for i := 0; i < len(pred.Terms); i++ {
			fID := f.Terms[i]
			pID := pred.Terms[i]

			if pID.Type() != TermTypeVariable && !fID.Equal(pID) {
				matches = false
				break
			}
		}

		if matches {
			res.Insert(f)
		}
	}
	return res
}

func (w *World) QueryRule(rule Rule, syms *SymbolTable) *FactSet {
	newFacts := &FactSet{}
	rule.Apply(w.facts, newFacts, syms)
	return newFacts
}

func (w *World) Clone() *World {
	newFacts := new(FactSet)
	*newFacts = *w.facts
	return &World{
		facts:     newFacts,
		rules:     append([]Rule{}, w.rules...),
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

func combine(
	variables MatchedVariables,
	predicates []Predicate,
	expressions []Expression,
	facts *FactSet,
	syms *SymbolTable,
) ([]MatchedVariables, error) {
	var res []MatchedVariables

	current := 0
	indexes := make([]int, len(predicates))

	// cannot apply a rule on an empty list of facts
	if len(predicates) > 0 && len(*facts) == 0 {
		return nil, nil
	}

	// main loop
	for {
		if len(predicates) > 0 && len(*facts) > 0 {
			// look for the next matching set of facts
			// current indicates which predicate we are looking at, and indexes contains
			// a list of indexes in the facts list, for each predicate
			// when we are done looking at a set of facts, the last index is incremented
			// and if that one reached the max number of facts, the previous one, etc
			for {
				if (*facts)[indexes[current]].Match(predicates[current]) {
					if current == len(predicates)-1 {
						// extract and check variables, check expressions, send variables
						break
					} else {
						current += 1
					}
				} else {
					// did not match, we either increase the current index or the previous one
					// then we check again for a match
					if !advanceIndexes(&current, &indexes, facts) {
						return res, nil
					}
				}
			}
		}

		// extract and check variables, check expressions, send variables
		var vars = variables.Clone()
		var matching = true

	match:
		for i, pred := range predicates {
			fact := (*facts)[indexes[i]]

			for j := 0; j < len(pred.Terms); j++ {
				term := pred.Terms[j]
				k, ok := term.(Variable)
				if !ok {
					continue
				}
				v := fact.Terms[j]
				if !vars.Insert(k, v) {
					matching = false
					break match
				}

			}
		}

		if matching {
			if complete_vars := vars.Complete(); complete_vars != nil {
				valid := true
				for _, e := range expressions {
					r, err := e.Evaluate(complete_vars, syms)
					if err != nil {
						return nil, err
					}
					if !r.Equal(Bool(true)) {
						valid = false
						break
					}
				}

				if valid {
					res = append(res, complete_vars)
				}
			} else {
				// if all predicates match but variables are not complete, it means
				// variables appearing in the head do not appear in the body,
				// so we should stop here because there's no way to get a correct match
				return res, nil
			}
		}

		// this was a rule or check with expressions but no predicates, no need to
		// update the indexes, an single execution is enough
		if len(predicates) == 0 {
			return res, nil
		}

		// next index
		if !advanceIndexes(&current, &indexes, facts) {
			return res, nil
		}
	}
}

func advanceIndexes(current *int, indexes *[]int, facts *FactSet) bool {
	for i := *current; i >= 0; i-- {
		if (*indexes)[i] < len(*facts)-1 {
			(*indexes)[i] += 1
			break
		} else {
			if i > 0 {
				(*indexes)[i] = 0
				*current -= 1
			} else {
				// we reached the first predicate, we cannot generate more
				// combinations, so we stop the task
				return false
			}
		}
	}
	return true
}
