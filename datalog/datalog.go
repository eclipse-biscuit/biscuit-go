// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package datalog

import (
	"bytes"
	"cmp"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"iter"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/eclipse-biscuit/biscuit-go/v2/internal/set"
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
	Compare(Term) int
	Equal(Term) bool
	Hash(*set.HashBuilder) *set.HashBuilder
	fmt.Stringer
}

// Set is a Term that contains other Terms, as a set.
type Set struct {
	*set.HashSet[Term]
}

func NewSet(terms ...Term) Set {
	return Set{
		HashSet: set.NewHashSet[Term](terms...),
	}
}

func (s Set) Type() TermType { return TermTypeSet }

func (s Set) Intersect(s2 Set) Set {
	return Set{s.HashSet.Intersect(s2.HashSet)}
}

func (s Set) Union(s2 Set) Set {
	return Set{s.HashSet.Union(s2.HashSet)}
}

func (s Set) Compare(s2 Term) int {
	if s2 == nil {
		return 1
	}
	if x := cmp.Compare(s.Type(), s2.Type()); x != 0 {
		return x
	}

	if s2, isSet := s2.(interface{ Iter() iter.Seq[Term] }); isSet {
		if x := set.Compared(s.Iter(), s2.Iter()); x != 0 {
			return x
		}
	} else {
		return cmp.Compare(s.Size(), 0) // This shouldn't happen
	}

	return 0
}

func (s Set) Hash(builder *set.HashBuilder) *set.HashBuilder {
	builder = builder.Byte(byte(s.Type()))
	for term := range s.Iter() {
		builder = builder.Hashable(term)
	}
	return builder
}

func (s Set) Equal(t Term) bool {
	return s.Compare(t) == 0
}

func (s Set) String() string {
	if s.Size() == 0 {
		return "{,}"
	}
	strSlice := make([]string, 0, s.Size())
	for _, t := range set.Sorted(s.HashSet.Iter()) {
		strSlice = append(strSlice, t.String())
	}
	sort.Strings(strSlice)
	return fmt.Sprintf("{%s}", strings.Join(strSlice, ", "))
}

var _ Term = (*Set)(nil)

type Variable uint32

func (Variable) Type() TermType { return TermTypeVariable }

func (v Variable) Compare(t Term) int {
	if t == nil {
		return 1
	}
	if x := cmp.Compare(v.Type(), t.Type()); x != 0 {
		return x
	}
	if v2, ok := t.(Variable); ok {
		return cmp.Compare(v, v2)
	}
	return 0 // We shouldn't get here
}

func (v Variable) Hash(builder *set.HashBuilder) *set.HashBuilder {
	return builder.
		Byte(byte(v.Type())).
		Uint64(uint64(v))
}

func (v Variable) Equal(t Term) bool {
	return v.Compare(t) == 0
}

func (v Variable) String() string {
	return fmt.Sprintf("$%d", v)
}

var _ Term = (*Variable)(nil)

type Integer int64

func (Integer) Type() TermType { return TermTypeInteger }

func (i Integer) Compare(t Term) int {
	if t == nil {
		return 1
	}
	if x := cmp.Compare(i.Type(), t.Type()); x != 0 {
		return x
	}
	if i2, ok := t.(Integer); ok {
		return cmp.Compare(i, i2)
	}
	return 0 // We shouldn't get here
}

func (i Integer) Hash(builder *set.HashBuilder) *set.HashBuilder {
	return builder.
		Byte(byte(i.Type())).
		Uint64(uint64(i))
}

func (i Integer) Equal(t Term) bool {
	return i.Compare(t) == 0
}

func (i Integer) String() string {
	return fmt.Sprintf("%d", i)
}

var _ Term = (*Integer)(nil)

type String uint64

func (String) Type() TermType { return TermTypeString }

func (s String) Compare(t Term) int {
	if t == nil {
		return 1
	}
	if x := cmp.Compare(s.Type(), t.Type()); x != 0 {
		return x
	}
	if s2, ok := t.(String); ok {
		return cmp.Compare(s, s2)
	}
	return 0 // We shouldn't get here
}

func (s String) Hash(builder *set.HashBuilder) *set.HashBuilder {
	return builder.
		Byte(byte(s.Type())).
		Uint64(uint64(s))
}

func (s String) Equal(t Term) bool {
	return s.Compare(t) == 0
}

func (s String) String() string {
	return fmt.Sprintf("#%d", s)
}

var _ Term = (*String)(nil)

type Date uint64

func (Date) Type() TermType { return TermTypeDate }

func (d Date) Compare(t Term) int {
	if t == nil {
		return 1
	}
	if x := cmp.Compare(d.Type(), t.Type()); x != 0 {
		return x
	}
	if d2, ok := t.(Date); ok {
		return cmp.Compare(d, d2)
	}
	return 0 // We shouldn't get here
}

func (d Date) Hash(builder *set.HashBuilder) *set.HashBuilder {
	return builder.
		Byte(byte(d.Type())).
		Uint64(uint64(d))
}

func (d Date) Equal(t Term) bool {
	return d.Compare(t) == 0
}

func (d Date) String() string {
	return time.Unix(int64(d), 0).UTC().Format(time.RFC3339)
}

var _ Term = (*Date)(nil)

type Bytes []byte

func (Bytes) Type() TermType { return TermTypeBytes }

func (b Bytes) Compare(t Term) int {
	if t == nil {
		return 1
	}
	if x := cmp.Compare(b.Type(), t.Type()); x != 0 {
		return x
	}
	if b2, ok := t.(Bytes); ok {
		return bytes.Compare(b, b2)
	}
	return 0 // We shouldn't get here
}

func (b Bytes) Hash(builder *set.HashBuilder) *set.HashBuilder {
	return builder.
		Byte(byte(b.Type())).
		Bytes(b)
}

func (b Bytes) Equal(t Term) bool {
	return b.Compare(t) == 0
}

func (b Bytes) String() string {
	return fmt.Sprintf("hex:%s", hex.EncodeToString(b))
}

var _ Term = (*Bytes)(nil)

type Bool bool

func (Bool) Type() TermType { return TermTypeBool }

func (b Bool) Compare(t Term) int {
	if t == nil {
		return 1
	}
	if x := cmp.Compare(b.Type(), t.Type()); x != 0 {
		return x
	}
	if b2, ok := t.(Bool); ok {
		return set.CompareBool(bool(b), bool(b2))
	}
	return 0 // We shouldn't get here
}

func (b Bool) Hash(builder *set.HashBuilder) *set.HashBuilder {
	return builder.
		Byte(byte(b.Type())).
		Bool(bool(b))
}

func (b Bool) Equal(t Term) bool {
	return b.Compare(t) == 0
}

func (b Bool) String() string {
	return fmt.Sprintf("%t", b)
}

var _ Term = (*Bool)(nil)

type Predicate struct {
	Name  String
	Terms []Term
}

func (p Predicate) Equal(p2 Predicate) bool {
	return p.Compare(p2) == 0
}

func (p Predicate) Compare(p2 Predicate) int {
	if x := cmp.Compare(p.Name, p2.Name); x != 0 {
		return x
	}
	if x := set.ComparedSlices(p.Terms, p2.Terms); x != 0 {
		return x
	}

	return 0
}

func (p Predicate) Hash(builder *set.HashBuilder) *set.HashBuilder {
	builder = builder.String(p.Name.String())
	for _, term := range p.Terms {
		builder = builder.Hashable(term)
	}
	return builder
}

var _ set.Ordered[Predicate] = (*Predicate)(nil)
var _ set.Equality[Predicate] = (*Predicate)(nil)
var _ set.Hashable[Predicate] = (*Predicate)(nil)

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

func (f Fact) Compare(f2 Fact) int {
	return f.Predicate.Compare(f2.Predicate)
}

func (f Fact) Equal(f2 Fact) bool {
	return f.Compare(f2) == 0
}

var _ set.Equality[Fact] = (*Fact)(nil)
var _ set.Hashable[Fact] = (*Fact)(nil)

type BlockID uint64

// Compare is used when ordering [[BlockID]]s.
// Authorizer block IDs come before other block IDs (it acts like -1). This is useful when sorting other elements by
// block ID. This ordering is required by the sample tests (and it makes sense).
func (i BlockID) Compare(j BlockID) int {
	iIsAuthorizer := i.IsAuthorizer()
	jIsAuthorizer := j.IsAuthorizer()

	if iIsAuthorizer && !jIsAuthorizer {
		return -1
	}
	if !iIsAuthorizer && jIsAuthorizer {
		return 1
	}

	return cmp.Compare(i, j)
}

func (i BlockID) Equal(j BlockID) bool {
	return i.Compare(j) == 0
}

func (i BlockID) String() string {
	return fmt.Sprintf("%d", i)
}

func (i BlockID) IsAuthorizer() bool {
	return uint64(i) == AuthorizerBlockID
}

func (i BlockID) Hash(builder *set.HashBuilder) *set.HashBuilder {
	return builder.Uint64(uint64(i))
}

var _ set.Equality[BlockID] = (*BlockID)(nil)
var _ set.Hashable[BlockID] = (*BlockID)(nil)

type Rule struct {
	Head        Predicate
	Body        []Predicate
	Expressions []Expression
	Scopes      []Scope
}

func (r Rule) Equal(r2 Rule) bool {
	return r.Compare(r2) == 0
}

func (r Rule) Compare(r2 Rule) int {
	if x := r.Head.Compare(r2.Head); x != 0 {
		return x
	}
	if x := set.ComparedSlices(r.Body, r2.Body); x != 0 {
		return x
	}
	if x := set.ComparedSlices(r.Expressions, r2.Expressions); x != 0 {
		return x
	}
	if x := set.ComparedSlices(r.Scopes, r2.Scopes); x != 0 {
		return x
	}

	return 0
}

func (r Rule) Hash(builder *set.HashBuilder) *set.HashBuilder {
	builder = builder.Hashable(r.Head)
	for _, pred := range r.Body {
		builder = builder.Hashable(pred)
	}
	for _, expr := range r.Expressions {
		builder = builder.Hashable(expr)
	}
	for _, scope := range r.Scopes {
		builder = builder.Hashable(scope)
	}
	return builder
}

var _ set.Equality[Rule] = (*Rule)(nil)
var _ set.Hashable[Rule] = (*Rule)(nil)

type InvalidRuleError struct {
	Rule            Rule
	MissingVariable Variable
}

func (e InvalidRuleError) Error() string {
	return fmt.Sprintf("datalog: variable %d in head is missing from body and/or constraints", e.MissingVariable)
}

func (r Rule) Apply(blockID BlockID, inputFacts FactSet, symbols *SymbolTable) (FactSet, error) {
	evaluator := newEvaluator(r.Body, r.Expressions, inputFacts, symbols)
	return evaluator.getNewFacts(r, blockID)
}

type CheckKind uint8

const (
	CheckOne CheckKind = iota
	CheckAll
	CheckReject
)

type Check struct {
	Queries []Rule
	Kind    CheckKind
}

func (c Check) Verify(
	factSet FactSet,
	blockScopes []Scope,
	blockID uint64,
	signatureRegistry SignatureRegistry,
	symbols *SymbolTable,
) (bool, error) {
	passing := c.Kind != CheckOne // Start with false for CheckOne, otherwise true
	for _, query := range c.Queries {
		trustedOrigin := *NewTrustedOriginFromScopes(
			blockScopes,
			query.Scopes,
			blockID,
			signatureRegistry,
		)
		filteredFacts := factSet.WithOrigin(trustedOrigin)
		evaluator := newEvaluator(query.Body, query.Expressions, *filteredFacts, symbols)

		switch c.Kind {
		case CheckAll:
			success, err := evaluator.verifyAllMatches()
			if err != nil {
				return false, err
			}
			if !success {
				passing = false
				break
			}
		case CheckReject:
			success, err := evaluator.verifyNoMatches()
			if err != nil {
				return false, err
			}
			if !success {
				passing = false
				break
			}
		default: // CheckOne is the default kind
			success, err := evaluator.verifyAnyMatches()
			if err != nil {
				return false, err
			}
			if success {
				return true, nil // Only one check required to pass
			}
		}
	}

	return passing, nil
}

// FactSet maps [Origin] (as encoded string) to sets of [Fact]s.
type FactSet map[string]*set.HashSet[Fact]

func NewFactSet(origin Origin, facts ...Fact) *FactSet {
	factSet := make(FactSet)
	factSet[origin.EncodeToString()] = set.NewHashSet(facts...)
	return &factSet
}

func (fs *FactSet) Origins() iter.Seq[Origin] {
	return func(yield func(Origin) bool) {
		for k := range *fs {
			if o, err := NewOriginFromString(k); err == nil {
				if !yield(*o) {
					return
				}
			}
		}
	}
}

func (fs *FactSet) Facts(origin Origin) iter.Seq[Fact] {
	key := origin.EncodeToString()
	return func(yield func(Fact) bool) {
		if factSet, exists := (*fs)[key]; exists {
			for fact := range factSet.Iter() {
				if !yield(fact) {
					return
				}
			}
		}
	}
}

func (fs *FactSet) AllFacts() iter.Seq[Fact] {
	return func(yield func(Fact) bool) {
		for origin := range fs.Origins() {
			for fact := range fs.Facts(origin) {
				if !yield(fact) {
					return
				}
			}
		}
	}
}

func (fs *FactSet) Iter() iter.Seq2[Origin, set.HashSet[Fact]] {
	return func(yield func(Origin, set.HashSet[Fact]) bool) {
		for strKey, factSet := range *fs {
			if o, err := NewOriginFromString(strKey); err == nil {
				if !yield(*o, *factSet) {
					return
				}
			}
		}
	}
}

func (fs *FactSet) IterSorted() iter.Seq2[Origin, set.HashSet[Fact]] {
	return func(yield func(Origin, set.HashSet[Fact]) bool) {
		// Collect all origin-factset pairs
		type factsWithOrigin struct {
			origin  Origin
			factSet set.HashSet[Fact]
		}

		pairs := make([]factsWithOrigin, 0, len(*fs))
		for origin, factSet := range fs.Iter() {
			pairs = append(pairs, factsWithOrigin{origin, factSet})
		}

		// Sort by origin: authorizer facts first, then block facts in ascending order
		slices.SortFunc(pairs, func(a, b factsWithOrigin) int {
			return a.origin.Compare(b.origin)
		})

		// Yield sorted pairs
		for _, p := range pairs {
			if !yield(p.origin, p.factSet) {
				return
			}
		}
	}
}

func (fs *FactSet) FilterByOrigin(trustedOrigin TrustedOrigin) iter.Seq2[Origin, set.HashSet[Fact]] {
	return func(yield func(Origin, set.HashSet[Fact]) bool) {
		for origin, factSet := range fs.Iter() {
			isSuperSet := trustedOrigin.IsSuperSet(&origin)
			if isSuperSet {
				if !yield(origin, factSet) {
					return
				}
			}
		}
	}
}

func (fs *FactSet) WithOrigin(trustedOrigin TrustedOrigin) *FactSet {
	result := make(FactSet)
	for origin, factSet := range fs.FilterByOrigin(trustedOrigin) {
		result[origin.EncodeToString()] = &factSet
	}
	return &result
}

func (fs *FactSet) Insert(origin Origin, fact Fact) {
	key := origin.EncodeToString()
	if factSet, exists := (*fs)[key]; exists {
		factSet.Insert(fact)
	} else {
		(*fs)[key] = set.NewHashSet(fact)
	}
}

func (fs *FactSet) InsertMulti(origin Origin, facts []Fact) {
	key := origin.EncodeToString()
	if factSet, exists := (*fs)[key]; exists {
		(*fs)[key] = factSet.Union(set.NewHashSet(facts...))
	} else {
		(*fs)[key] = set.NewHashSet(facts...)
	}
}

func (fs *FactSet) InsertNew(origin Origin, fact Fact) bool {
	key := origin.EncodeToString()
	if factSet, exists := (*fs)[key]; exists {
		if !factSet.Insert(fact) {
			return false
		}
	} else {
		(*fs)[key] = set.NewHashSet(fact)
	}

	return true
}

// Count all the Facts for all origins.
func (fs *FactSet) Count() uint64 {
	count := uint64(0)
	for _, facts := range *fs {
		count += uint64(facts.Size())
	}
	return count
}

func (fs *FactSet) Clone() *FactSet {
	result := make(FactSet)
	for strKey, factSet := range *fs {
		result[strKey] = factSet.Clone()
	}
	return &result
}

func (fs *FactSet) keys() []string {
	keys := make([]string, 0, len(*fs))
	for strKey := range *fs {
		keys = append(keys, strKey)
	}
	slices.Sort(keys)
	return keys
}

func (fs *FactSet) Compare(fs2 *FactSet) int {
	if fs2 == nil {
		return 1
	}

	// Compare the length of the maps.
	if x := cmp.Compare(len(*fs), len(*fs2)); x != 0 {
		return x
	}

	// Check if both are empty.
	if len(*fs) == 0 {
		return 0
	}

	// Make slices of keys for the maps.
	fsKeys1 := fs.keys()
	fsKeys2 := fs2.keys()

	// Compare the keys for the two maps.
	if c := slices.Compare(fsKeys1, fsKeys2); c != 0 {
		return c
	}

	// Compare the values in the two maps.
	for _, key := range fsKeys1 {
		if x := set.Compared((*fs)[key].Iter(), (*fs2)[key].Iter()); x != 0 {
			return x
		}
	}

	return 0
}

func (fs *FactSet) Equal(fs2 *FactSet) bool {
	return fs.Compare(fs2) == 0
}

type RuleInBlock struct {
	BlockID BlockID
	Rule    Rule
}

// Apply delegates to the Rule's `Apply`. It is here just for convenience.
func (r RuleInBlock) Apply(inputFacts FactSet, symbols *SymbolTable) (FactSet, error) {
	return r.Rule.Apply(r.BlockID, inputFacts, symbols)
}

func (r RuleInBlock) Compare(r2 RuleInBlock) int {
	if x := cmp.Compare(r.BlockID, r2.BlockID); x != 0 {
		return x
	}
	return r.Rule.Compare(r2.Rule)
}

func (r RuleInBlock) Equal(r2 RuleInBlock) bool {
	return r.Compare(r2) == 0
}

func (r RuleInBlock) Hash(builder *set.HashBuilder) *set.HashBuilder {
	return builder.
		Hashable(r.BlockID).
		Hashable(r.Rule)
}

// RuleSet maps [TrustedOrigin] (as encoded string) to sets of [RuleInBlock]s.
type RuleSet map[string]*set.HashSet[RuleInBlock]

func NewRuleSet(origin TrustedOrigin, blockID BlockID, rules ...Rule) *RuleSet {
	ruleSet := make(RuleSet)
	ribs := set.NewHashSet[RuleInBlock]()
	for _, rule := range rules {
		ribs.Insert(RuleInBlock{
			BlockID: blockID,
			Rule:    rule,
		})
	}
	ruleSet[origin.EncodeToString()] = ribs
	return &ruleSet
}

func (rs *RuleSet) TrustedOrigins() iter.Seq[TrustedOrigin] {
	return func(yield func(TrustedOrigin) bool) {
		for k := range *rs {
			if to, err := NewTrustedOriginFromString(k); err == nil {
				if !yield(*to) {
					return
				}
			}
		}
	}
}

func (rs *RuleSet) Rules(trustedOrigin TrustedOrigin) iter.Seq2[BlockID, Rule] {
	key := trustedOrigin.EncodeToString()
	return func(yield func(BlockID, Rule) bool) {
		if ruleInBlockSet, exists := (*rs)[key]; exists {
			for rib := range ruleInBlockSet.Iter() {
				if !yield(rib.BlockID, rib.Rule) {
					return
				}
			}
		}
	}
}

func (rs *RuleSet) AllRules() iter.Seq[Rule] {
	return func(yield func(Rule) bool) {
		for trustedOrigin := range rs.TrustedOrigins() {
			for _, rule := range rs.Rules(trustedOrigin) {
				if !yield(rule) {
					return
				}
			}
		}
	}
}

func (rs *RuleSet) Iter() iter.Seq2[TrustedOrigin, set.HashSet[RuleInBlock]] {
	return func(yield func(TrustedOrigin, set.HashSet[RuleInBlock]) bool) {
		for strKey, ruleInBlockSet := range *rs {
			if to, err := NewTrustedOriginFromString(strKey); err == nil {
				if !yield(*to, *ruleInBlockSet) {
					return
				}
			}
		}
	}
}

// RulesByBlockID yields rules, organized by block ID.
// To yield deterministic results, the block IDs and rules are sorted.
func (rs *RuleSet) RulesByBlockID() iter.Seq2[BlockID, []Rule] {
	return func(yield func(BlockID, []Rule) bool) {
		// Gather the rules, organized by block ID
		rulesByBlockID := make(map[BlockID]*set.HashSet[Rule])
		for _, ruleInBlocks := range rs.Iter() {
			for ruleInBlock := range ruleInBlocks.Iter() {
				blockID, rule := ruleInBlock.BlockID, ruleInBlock.Rule
				if rulesSet, wasFound := rulesByBlockID[blockID]; wasFound {
					rulesSet.Insert(rule)
				} else {
					rulesByBlockID[blockID] = set.NewHashSet(rule)
				}
			}
		}

		// Gather and sort block IDs
		blockIDsSorted := make([]BlockID, len(rulesByBlockID))
		{
			index := 0
			for blockID := range rulesByBlockID {
				blockIDsSorted[index] = blockID
				index++
			}
		}
		slices.Sort(blockIDsSorted)

		// Yield the rules.
		for _, blockID := range blockIDsSorted {
			if !yield(blockID, set.Sorted(rulesByBlockID[blockID].Iter())) {
				return
			}
		}
	}
}

func (rs *RuleSet) Insert(trustedOrigin TrustedOrigin, blockID BlockID, rule Rule) {
	key := trustedOrigin.EncodeToString()
	newRuleInBlock := RuleInBlock{blockID, rule}
	if ruleInBlockSet, exists := (*rs)[key]; exists {
		ruleInBlockSet.Insert(newRuleInBlock)
	} else {
		(*rs)[key] = set.NewHashSet(newRuleInBlock)
	}
}

func (rs *RuleSet) InsertMulti(trustedOrigin TrustedOrigin, blockID BlockID, rules []Rule) {
	key := trustedOrigin.EncodeToString()
	newRuleInBlocks := make([]RuleInBlock, len(rules))
	for i, rule := range rules {
		newRuleInBlocks[i] = RuleInBlock{blockID, rule}
	}
	if existingRuleInBlockSet, exists := (*rs)[key]; exists {
		(*rs)[key] = existingRuleInBlockSet.Union(set.NewHashSet(newRuleInBlocks...))
	} else {
		(*rs)[key] = set.NewHashSet(newRuleInBlocks...)
	}
}

// Count returns the number of rules in the [RuleSet].
// Counting is done by distinct trusted origin, so the same rule shared by two trusted origins is counted twice.
func (rs *RuleSet) Count() uint64 {
	count := uint64(0)
	for _, ruleSet := range *rs {
		count += uint64(ruleSet.Size())
	}
	return count
}

func (rs *RuleSet) Clone() *RuleSet {
	result := make(RuleSet)
	for strKey, ruleSet := range *rs {
		result[strKey] = ruleSet.Clone()
	}
	return &result
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
	Facts FactSet
	Rules RuleSet

	runLimits runLimits
}

func NewWorld(opts ...WorldOption) *World {
	w := &World{
		Facts:     make(FactSet),
		Rules:     make(RuleSet),
		runLimits: defaultRunLimits,
	}

	for _, opt := range opts {
		opt(w)
	}

	return w
}

func (w *World) AddFact(origin Origin, fact Fact) {
	w.Facts.Insert(origin, fact)
}

func (w *World) InsertFacts(origin Origin, facts []Fact) {
	w.Facts.InsertMulti(origin, facts)
}

func (w *World) AddRule(trustedOrigin TrustedOrigin, blockID BlockID, rule Rule) {
	w.Rules.Insert(trustedOrigin, blockID, rule)
}

func (w *World) ResetRules() {
	w.Rules = RuleSet{}
}

func (w *World) NumRules() uint64 {
	return w.Rules.Count()
}

func (w *World) Run(symbols *SymbolTable) error {
	done := make(chan error)
	ctx, cancel := context.WithTimeout(context.Background(), w.runLimits.maxDuration)
	defer cancel()

	go func() {
		for i := 0; i < w.runLimits.maxIterations; i++ {
			select {
			case <-ctx.Done():
				return
			default:
				newFacts := make(FactSet)

				for trustedOrigin, ruleInBlockSet := range w.Rules.Iter() {
					filteredFacts := w.Facts.WithOrigin(trustedOrigin)

					for rib := range ruleInBlockSet.Iter() {

						select {
						case <-ctx.Done():
							return
						default:
							resultFacts, err := rib.Apply(
								*filteredFacts,
								symbols,
							)
							if err != nil {
								done <- err
								return
							}

							for origin, facts := range resultFacts.Iter() {
								newFacts.InsertMulti(origin, slices.Collect(facts.Iter()))
							}
						}

					}
				}

				prevCount := w.Facts.Count()
				for origin, facts := range newFacts.Iter() {
					w.Facts.InsertMulti(origin, slices.Collect(facts.Iter()))
				}

				newCount := w.Facts.Count()
				if newCount >= uint64(w.runLimits.maxFacts) {
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
	res := make(FactSet)

	for origin, factSet := range w.Facts.Iter() {
		for fact := range factSet.Iter() {
			if fact.Predicate.Name != pred.Name {
				continue
			}

			// if the predicate has a different number of IDs
			// the fact must not match
			if len(fact.Predicate.Terms) != len(pred.Terms) {
				continue
			}

			matches := true
			for i := 0; i < len(pred.Terms); i++ {
				fID := fact.Predicate.Terms[i]
				pID := pred.Terms[i]

				if pID.Type() != TermTypeVariable {
					if fID.Type() != pID.Type() || fID != pID {
						matches = false
						break
					}

				}
			}

			if matches {
				res.Insert(origin, fact)
			}
		}

	}

	return &res
}

func (w *World) QueryRule(
	rule Rule,
	trustedOrigin TrustedOrigin,
	symbols *SymbolTable,
) (FactSet, error) {
	return rule.Apply(
		BlockID(AuthorizerBlockID),
		*w.Facts.WithOrigin(trustedOrigin),
		symbols,
	)
}

func (w *World) Clone() *World {
	return &World{
		Facts:     *w.Facts.Clone(),
		Rules:     *w.Rules.Clone(),
		runLimits: w.runLimits,
	}
}
