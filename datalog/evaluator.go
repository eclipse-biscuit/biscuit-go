package datalog

import (
	"iter"
)

// `evaluator.go` provides the core Datalog evaluation engine for biscuit tokens.
//
// # A three-layer architecture is used to decouple the Datalog evaluation logic.
//
// ## Layer 1: [[combinations]]
// - Generates all possible predicate/fact combinations using an []int slice.
// - Implements the odometer pattern with backtracking for efficient combination search.
// - Provides branch elimination while searching through combinations.
// - Yields [i, j, k, ...] arrays, with each value representing an index into a fact slice that will be tested
//   against a predicate matching its location in the slice. Each fact is tested against a different predicate.
//
// ## Layer 2: [[combineIt]] (matching without expression evaluation)
// - This middle layer is exposed so that we can find matches and expose expression evaluation for "check all"
//   datalog evaluation. Handy separation of concerns. Mimics the Rust reference code.
// - Consumes [[combinations]] from layer 1.
// - Searches for matching predicates and facts.
// - Unifies variables across fact and predicate matches.
// - Yields variables and their origin.
// - Does not evaluate expressions.
//
// ## Layer 3: [[evaluator]] (expression evaluation)
// - Used directly by [[Rule]] and [[Check]]
// - Consumes [[combineIt]] from Layer 2.
// - Evaluates expressions on variable bindings.
// - Derives new rules and applies specific check kind semantics.
//
// # Why separate the Datalog evaluation into components?
//
// Separation of concerns improves readability and testability. Datalog evaluation is a complex topic and tightly
// coupled code is hard to understand. Isolated components can be tested separately, which proves proper
// functionality and allows developers to see how it works.
//
// We need to separate fact/predicate matching from expression evaluation for different checking strategies to work.
//
// # Usage
//
// Consumers should construct an `evaluator` and call its methods.

// factWithOrigin is used whenever a [[Fact]] needs to be associated with an [[Origin]]
// during Datalog evaluation.
type factWithOrigin struct {
	Fact
	Origin Origin
}

// getFactWithOrigins is a helper that converts a [[FactSet]] into a slice of [[factWithOrigin]] structs.
func getFactWithOrigins(factSet FactSet) []factWithOrigin {
	result := make([]factWithOrigin, factSet.Count())

	{
		i := 0
		for origin, facts := range factSet.Iter() {
			for fact := range facts.Iter() {
				result[i] = factWithOrigin{fact, origin}
				i++
			}
		}
	}

	return result
}

// matchedVariables is used while searching for matching predicates and facts during datalog
// evaluation to store variables while comparing them between the predicates and facts, and
// to return matches that are found. These are used while deriving new facts or while verifying
// checks.
type matchedVariables map[Variable]*Term

// insert stores a new [[Term]] that matches a [[Variable]].
// Returns true if the entry is new or if it was already stored.
// Returns false if there was already an entry that is different from this new one (keeping the old value).
func (m matchedVariables) insert(k Variable, v Term) bool {
	existing := m[k]
	if existing == nil {
		m[k] = &v
		return true
	}
	return v.Equal(*existing)
}

// complete is called when predicate and fact variable matching is complete. If any variable
// does not have a [[Term]] associated with it, the match has failed, so nil is returned.
func (m matchedVariables) complete() map[Variable]*Term {
	for _, v := range m {
		if v == nil {
			return nil
		}
	}
	return (map[Variable]*Term)(m)
}

// clone makes a copy of the [[matchedVariables]].
func (m matchedVariables) clone() matchedVariables {
	res := make(matchedVariables, len(m))
	for k, v := range m {
		res[k] = v
	}
	return res
}

// newMatchedVariables constructs a [[matchedVariable]], for the given predicates, finding [[Variable]]
// terms and filtering out other terms. The [[Term]] values are nil, so this acts as a template that will
// be cloned, filled out, and completed.
func newMatchedVariables(predicates []Predicate) matchedVariables {
	result := make(matchedVariables)

	for _, predicate := range predicates {
		for _, term := range predicate.Terms {
			variableTerm, isVariableTerm := term.(Variable)
			if !isVariableTerm {
				continue
			}
			result[variableTerm] = nil
		}
	}

	return result
}

// matchResult combines [[matchedVariables]] with its [[Origin]]. This is used when iterating new matches.
type matchResult struct {
	variables matchedVariables
	origin    *Origin
}

// evaluator is used by [[Rule]] to create new facts and by [[Check]] for verification. It has methods that
// evaluate predicates, find matching facts, derive new facts, and evaluate expressions.
type evaluator struct {
	combineIt   *combineIt
	expressions []Expression
	symbols     *SymbolTable
}

// newEvaluator constructs a new [[evaluator]].
func newEvaluator(
	predicates []Predicate,
	expressions []Expression,
	factSet FactSet,
	symbols *SymbolTable,
) *evaluator {
	return &evaluator{
		combineIt:   newCombineIt(predicates, factSet),
		expressions: expressions,
		symbols:     symbols,
	}

}

// getNewFacts is the core datalog evaluation entry point for deriving new facts from a [[Rule]].
func (e *evaluator) getNewFacts(rule Rule, blockID BlockID) (FactSet, error) {
	resultFacts := make(FactSet)

	baseOrigin := NewOrigin(uint64(blockID))

	for match, err := range e.getValidMatches() {
		if err != nil {
			return nil, err
		}

		origin := baseOrigin.clone()
		if match.origin != nil {
			origin.InsertOrigin(match.origin)
		}
		variables := match.variables

		predicate := rule.Head.Clone()
		for termIndex, term := range predicate.Terms {
			if variable, ok := term.(Variable); ok {
				if matchedTerm, ok := variables[variable]; ok {
					predicate.Terms[termIndex] = *matchedTerm
				} else {
					return nil, InvalidRuleError{rule, variable}
				}
			} else {
				continue
			}
		}

		resultFacts.Insert(
			*origin,
			Fact{Predicate: predicate},
		)
	}

	return resultFacts, nil
}

// getValidMatches finds predicate and fact combinations with valid expression evaluation.
// This is used for [[Rule]] evaluation.
func (e *evaluator) getValidMatches() iter.Seq2[*matchResult, error] {
	return func(yield func(*matchResult, error) bool) {
		for origin, variables := range e.combineIt.matches() {
			valid := true
			for _, expression := range e.expressions {
				res, err := expression.Evaluate(variables, e.symbols)
				if err != nil {
					// Yield the error.
					if !yield(nil, err) {
						return
					}

					// There was an error, so we stop yielding results.
					return
				}

				// If any expression evaluates to false, then the match is invalid.
				if !res.Equal(Bool(true)) {
					valid = false
					break
				}

			}

			if valid {
				// Yield a match result
				result := matchResult{
					variables: variables,
					origin:    origin,
				}
				if !yield(&result, nil) {
					return
				}
			}
		}
	}
}

// verifyAnyMatches evaluates a [[Check]] with [[CheckOne]] semantics.
// Returns true if, for ANY ONE matching check, all expressions are true.
func (e *evaluator) verifyAnyMatches() (bool, error) {
	for _, variables := range e.combineIt.matches() {
		success := true
		for _, expression := range e.expressions {
			result, err := expression.Evaluate(variables, e.symbols)
			if err != nil {
				return false, err
			}

			if !result.Equal(Bool(true)) {
				success = false
				break
			}
		}

		if success {
			return true, nil
		}
	}

	return false, nil
}

// verifyAllMatches evaluates a [[Check]] with [[CheckAll]] semantics.
// Returns true if, for ALL matching checks, all expressions are true.
func (e *evaluator) verifyAllMatches() (bool, error) {
	found := false

	for _, variables := range e.combineIt.matches() {
		found = true

		for _, expression := range e.expressions {
			result, err := expression.Evaluate(variables, e.symbols)
			if err != nil {
				return false, err
			}

			if !result.Equal(Bool(true)) {
				return false, nil
			}
		}
	}

	return found, nil
}

// verifyNoMatches evaluates a [[Check]] with [[CheckReject]] semantics.
// Returns true if, for ALL matching checks, NO expressions are true.
func (e *evaluator) verifyNoMatches() (bool, error) {
	for _, variables := range e.combineIt.matches() {
		for _, expression := range e.expressions {
			result, err := expression.Evaluate(variables, e.symbols)
			if err != nil {
				return false, err
			}

			if result.Equal(Bool(true)) {
				return false, nil
			}
		}
	}

	return true, nil
}

// combineIt is used to create an iterator for rule application. It searches for matches between predicates and facts
// without evaluating expressions. This structure, which is named after a similar iterator in the Rust reference code,
// is meant to be used by the [[evaluator]].
type combineIt struct {
	variables  matchedVariables
	predicates []Predicate
	allFacts   []factWithOrigin
	symbols    *SymbolTable
}

// newCombineIt constructs a new [[combineIt]].
func newCombineIt(predicates []Predicate, factSet FactSet) *combineIt {
	return &combineIt{
		variables:  newMatchedVariables(predicates),
		predicates: predicates,
		allFacts:   getFactWithOrigins(factSet),
	}
}

// matches returns an iterator for [[Origin]] and [[matchedVariables]] for predicate and fact matching. It uses
// [[combinations]] to search through all possible match combinations and checks the indexed predicates and facts
// for matches.
func (ci *combineIt) matches() iter.Seq2[*Origin, matchedVariables] {
	var failedAtIndex func(int)
	var indexesSeq iter.Seq[[]int]
	{
		c := combinations{
			predicateCount: len(ci.predicates),
			factCount:      len(ci.allFacts),
		}
		indexesSeq, failedAtIndex = c.iter()
	}

	return func(yield func(*Origin, matchedVariables) bool) {
	indexes:
		for indexes := range indexesSeq {
			// Compare facts and predicates and check for matches
		matches:
			for predicateIndex, factIndex := range indexes {
				if ci.allFacts[factIndex].Match(ci.predicates[predicateIndex]) {
					if predicateIndex == len(ci.predicates)-1 {
						break matches // Only breaks on LAST predicate
					}
				} else {
					failedAtIndex(predicateIndex)
					continue indexes
				}
			}

			// Gather variables and determine if we are still matching
			variables := ci.variables.clone()
			for predicateIndex, predicate := range ci.predicates {
				fact := ci.allFacts[indexes[predicateIndex]].Fact
				for termIndex, predicateTerm := range predicate.Terms {
					if variable, ok := predicateTerm.(Variable); ok {
						factTerm := fact.Predicate.Terms[termIndex]
						if !variables.insert(variable, factTerm) {
							failedAtIndex(predicateIndex)
							continue indexes
						}
					}
				}
			}

			// Yield if we are still matching
			// Note: We don't evaluate expressions; that is decoupled
			if completedVars := variables.complete(); completedVars != nil {
				var origin *Origin

				// Union the origins from all facts.
				if len(indexes) > 0 {
					origin = ci.allFacts[indexes[0]].Origin.clone()
					for i := 1; i < len(indexes); i++ {
						origin.InsertOrigin(&ci.allFacts[indexes[i]].Origin)
					}
				}

				if !yield(origin, completedVars) {
					return
				}

			}
		}
	}
}

// combinations is a cartesian product generator for fact indexes and predicates.
// This is used by [[combineIt]] to search through all combinations of facts and
// predicates, while allowing for some backtracking and combination branch pruning.
//
// This exists mainly to extract and isolate some of the datalog evaluation algorithm
// into a distinct, testable component.
//
// This implements the "odometer" pattern and provides an iterator over slice values
// that can be thought of as a mixed-radix number with base factCount.
type combinations struct {
	predicateCount int
	factCount      int
}

// newIncrementAt creates a closure used by `combinations.iter` to enable the caller
// to update the state of the iterator to skip over impossible match combinations.
// When a predicate in an array of fact indexes fails to match, calling `failedAtIndex`
// increments the indexes at that location and resets all subsequent positions to 0.
// This pruning behaviour is similar to backtracking in a depth-first search: when a
// match fails, we advance to the next possibility at the failure point rather than
// exploring more impossible combinations.
func newIncrementAt(indexes *[]int, factCount, predicateCount int, done, failed *bool) func(int) {
	return func(failedAtIndex int) {
		if failedAtIndex < 0 || failedAtIndex >= predicateCount {
			return
		}

		*failed = true
		position := failedAtIndex

		for position >= 0 {
			if (*indexes)[position] < factCount-1 {
				(*indexes)[position] += 1

				for p2 := position + 1; p2 < predicateCount; p2++ {
					(*indexes)[p2] = 0
				}

				return
			} else {
				(*indexes)[position] = 0
				position--
			}
		}

		*done = true
	}
}

// newIncrement creates a closure used by `combinations.iter` to advance the `indexes` slice
// to the next combination, starting in the rightmost position (like incrementing a normal
// number). This is the default increment function used after a successful match is yielded
// (when the caller has not called `failedAtIndex`). Unlike the closure returned by
// [[newIncrementAt]], this does not skip over any of the search space.
func newIncrement(indexes *[]int, factCount, predicateCount int, done *bool) func() {
	return func() {
		position := predicateCount - 1

		for position >= 0 {
			if (*indexes)[position] < factCount-1 {
				(*indexes)[position] += 1
				return
			} else {
				(*indexes)[position] = 0
				position--
			}
		}

		*done = true
	}
}

// iter returns an iterator over all combination of fact indexes, one index per predicate
// position (essentially a cartesian product of integers 0 to factCount-1).
// Each yielded []int slice is predicateCount elements long, where slice[i] is the
// fact index to use for one predicate while matching.
// The returned `failedAtIndex` function allows the caller to signal when a match fails,
// indicating the predicate position in the slice. This enables the iterator to skip
// impossible combinations and potentially yielding fewer results than the full cartesian
// product.
func (c *combinations) iter() (iterator iter.Seq[[]int], failedAtIndex func(int)) {
	// Empty body (no predicates) is an unconditional success: yield once
	if c.predicateCount == 0 {
		iterator = func(yield func([]int) bool) {
			yield([]int{})
		}
		failedAtIndex = func(int) { return }
		return
	}

	// No facts (no matches possible): Don't yield
	if c.factCount == 0 {
		iterator = func(yield func([]int) bool) {
			return
		}
		failedAtIndex = func(int) { return }
		return
	}

	// Internal state
	indexes := make([]int, c.predicateCount)
	done := false
	failed := false

	// Build the incrementing functions.
	failedAtIndex = newIncrementAt(&indexes, c.factCount, c.predicateCount, &done, &failed)
	increment := newIncrement(&indexes, c.factCount, c.predicateCount, &done)

	// Build the `iterator` iterator.
	iterator = func(yield func([]int) bool) {
		// Always yield the first value
		if !yield(indexes) {
			return
		}

		// Yield more values
		for !done {
			if failed {
				failed = false
			} else {
				increment()
			}

			if done {
				break
			}

			if !yield(indexes) {
				return
			}
		}
	}

	return
}
