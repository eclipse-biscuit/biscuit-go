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

type Set []Term

func (Set) Type() TermType { return TermTypeSet }
func (s Set) Equal(t Term) bool {
	c, ok := t.(Set)
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
func (s Set) String() string {
	eltStr := make([]string, 0, len(s))
	for _, e := range s {
		eltStr = append(eltStr, e.String())
	}
	sort.Strings(eltStr)
	return fmt.Sprintf("[%s]", strings.Join(eltStr, ", "))
}
func (s Set) Intersect(t Set) Set {
	other := make(map[Term]struct{}, len(t))
	for _, v := range t {
		other[v] = struct{}{}
	}

	result := Set{}

	for _, id := range s {
		if _, ok := other[id]; ok {
			result = append(result, id)
		}
	}
	return result
}
func (s Set) Union(t Set) Set {
	this := make(map[Term]struct{}, len(s))
	for _, v := range s {
		this[v] = struct{}{}
	}

	result := Set{}
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

	combinations := combine(variables, r.Body, r.Expressions, facts, syms)

	for res := range combinations {
		if res.error != nil {
			return res.error
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

func (w *World) Run(ctx context.Context, syms *SymbolTable) error {
	done := make(chan error)
	ctx, cancel := context.WithTimeout(ctx, w.runLimits.maxDuration)
	defer cancel()

	go func() {
		for i := 0; i < w.runLimits.maxIterations; i++ {
			select {
			case <-ctx.Done():
				return
			default:
				var newFacts FactSet
				for _, r := range w.rules {
					select {
					case <-ctx.Done():
						return
					default:
						if err := r.Apply(w.facts, &newFacts, syms); err != nil {
							done <- err
							return
						}
					}
				}

				prevCount := len(*w.facts)
				w.facts.InsertAll([]Fact(newFacts))

				newCount := len(*w.facts)
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

func (w *World) Query(pred Predicate) *FactSet {
	res := &FactSet{}
	for _, f := range *w.facts {
		if f.Predicate.Name != pred.Name {
			continue
		}

		// if the predicate has a different number of IDs
		// the fact must not match
		if len(f.Predicate.Terms) != len(pred.Terms) {
			continue
		}

		matches := true
		for i := 0; i < len(pred.Terms); i++ {
			fID := f.Predicate.Terms[i]
			pID := pred.Terms[i]

			if pID.Type() != TermTypeVariable {
				if fID.Type() != pID.Type() || fID != pID {
					matches = false
					break
				}

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

func combine(variables MatchedVariables, predicates []Predicate, expressions []Expression, facts *FactSet, syms *SymbolTable) <-chan struct {
	MatchedVariables
	error
} {
	c := make(chan struct {
		MatchedVariables
		error
	})

	go func(c chan struct {
		MatchedVariables
		error
	}) {
		defer close(c)

		current := 0
		indexes := make([]int, len(predicates))
		//fmt.Printf("combine variables %+v preds %+v exp %+v facts %+v indexes %+v\n", variables, predicates, expressions, *facts, indexes)

		// cannot apply a rule on an empty list of facts
		if len(predicates) > 0 && len(*facts) == 0 {
			return
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
							return
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
				//fmt.Printf("evaluating predicate(%d) %+v with fact %+v\n", i, pred, fact)

				for j := 0; j < len(pred.Terms); j++ {
					term := pred.Terms[j]
					k, ok := term.(Variable)
					if !ok {
						continue
					}
					v := fact.Predicate.Terms[j]
					if !vars.Insert(k, v) {
						matching = false
						break match
					}

				}
			}

			//fmt.Printf("evaluating indexes %+v with extracted variables %+v, matching = %+v\n", indexes, variables, matching)
			if matching {
				if complete_vars := vars.Complete(); complete_vars != nil {
					//fmt.Printf("variables are complete, evaluating expressions\n")
					valid := true
					for _, e := range expressions {
						res, err := e.Evaluate(complete_vars, syms)
						if err != nil {
							fmt.Printf("expression error: %+v", err)
							c <- struct {
								MatchedVariables
								error
							}{complete_vars, err}

							return
						}
						if !res.Equal(Bool(true)) {
							valid = false
							break
						}
					}

					if valid {
						//fmt.Printf("sending valid variables %+v\n", complete_vars)
						c <- struct {
							MatchedVariables
							error
						}{complete_vars, nil}
					}
				} else {
					// if all predicates match but variables are not complete, it means
					// variables appearing in the head do not appear in the body,
					// so we should stop here because there's no way to get a correct match
					return
				}
			}

			// this was a rule or check with expressions but no predicates, no need to
			// update the indexes, an single execution is enough
			if len(predicates) == 0 {
				return
			}

			// next index
			if !advanceIndexes(&current, &indexes, facts) {
				return
			}
		}

	}(c)
	return c
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
