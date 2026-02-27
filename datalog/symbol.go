// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package datalog

import (
	"fmt"
	"sort"
	"strings"

	"github.com/eclipse-biscuit/biscuit-go/v2/internal/set"
	"github.com/eclipse-biscuit/biscuit-go/v2/pb"
)

var DEFAULT_SYMBOLS = [...]string{
	"read",
	"write",
	"resource",
	"operation",
	"right",
	"time",
	"role",
	"owner",
	"tenant",
	"namespace",
	"user",
	"team",
	"service",
	"admin",
	"email",
	"group",
	"member",
	"ip_address",
	"client",
	"client_ip",
	"domain",
	"path",
	"version",
	"cluster",
	"node",
	"hostname",
	"nonce",
	"query",
}

var OFFSET = 1024

type SymbolTable []string

func (t *SymbolTable) Insert(s string) String {
	for i, v := range DEFAULT_SYMBOLS {
		if string(v) == s {
			return String(i)
		}
	}

	for i, v := range *t {
		if string(v) == s {
			return String(OFFSET + i)
		}
	}
	*t = append(*t, s)

	return String(OFFSET + len(*t) - 1)
}

func (t *SymbolTable) Sym(s string) Term {
	for i, v := range DEFAULT_SYMBOLS {
		if string(v) == s {
			return String(i)
		}
	}

	for i, v := range *t {
		if string(v) == s {
			return String(OFFSET + i)
		}
	}
	return nil
}

func (t *SymbolTable) Index(s string) uint64 {
	for i, v := range DEFAULT_SYMBOLS {
		if string(v) == s {
			return uint64(i)
		}
	}

	for i, v := range *t {
		if string(v) == s {
			return uint64(OFFSET + i)
		}
	}
	panic("index not found")
}

func (t *SymbolTable) Str(sym String) string {
	if int(sym) < 1024 {
		if int(sym) > len(DEFAULT_SYMBOLS)-1 {
			return fmt.Sprintf("<invalid symbol %d>", sym)
		} else {
			return DEFAULT_SYMBOLS[int(sym)]
		}
	}
	if int(sym)-1024 > len(*t)-1 {
		return fmt.Sprintf("<invalid symbol %d>", sym)
	}
	return (*t)[int(sym)-1024]
}

func (t *SymbolTable) Var(v Variable) string {
	if int(v) < 1024 {
		if int(v) > len(DEFAULT_SYMBOLS)-1 {
			return fmt.Sprintf("<invalid variable %d>", v)
		} else {
			return DEFAULT_SYMBOLS[int(v)]
		}
	}
	if int(v)-1024 > len(*t)-1 {
		return fmt.Sprintf("<invalid variable %d>", v)
	}
	return (*t)[int(v)-1024]
}

func (t *SymbolTable) Clone() *SymbolTable {
	newTable := *t
	return &newTable
}

// SplitOff returns a newly allocated slice containing the elements in the range
// [at, len). After the call, the receiver will be left containing
// the elements [0, at) with its previous capacity unchanged.
func (t *SymbolTable) SplitOff(at int) *SymbolTable {
	if at > len(*t) {
		panic("split index out of bound")
	}

	newTable := make(SymbolTable, len(*t)-at)
	copy(newTable, (*t)[at:])

	*t = (*t)[:at]

	return &newTable
}

func (t *SymbolTable) Len() int {
	return len(*t)
}

// IsDisjoint returns true if receiver has no elements in common with other.
// This is equivalent to checking for an empty intersection.
func (t *SymbolTable) IsDisjoint(other *SymbolTable) bool {
	m := make(map[string]struct{}, len(*t))
	for _, s := range *t {
		m[s] = struct{}{}
	}

	for _, os := range *other {
		if _, ok := m[os]; ok {
			return false
		}
	}

	return true
}

// Extend insert symbols from the given SymbolTable in the receiving one
// excluding any Symbols already existing
func (t *SymbolTable) Extend(other *SymbolTable) {
	for _, s := range *other {
		t.Insert(s)
	}
}

// FormatTerm recursively formats a term, resolving String symbols and handling Sets
func (t *SymbolTable) FormatTerm(term Term) string {
	switch v := term.(type) {
	case String:
		return fmt.Sprintf("\"%s\"", t.Str(v))
	case Variable:
		return fmt.Sprintf("$%s", t.Var(v))
	case Set:
		elements := make([]string, 0, v.Size())
		for _, elem := range set.Sorted(v.Iter()) {
			elements = append(elements, t.FormatTerm(elem)) // Recursive call
		}
		// Empty sets use {,} format per Biscuit spec
		if len(elements) == 0 {
			return "{,}"
		}
		return "{" + strings.Join(elements, ", ") + "}"
	default:
		return fmt.Sprintf("%v", term)
	}
}

type SymbolDebugger struct {
	*SymbolTable
	*PublicKeyTable
}

func (d SymbolDebugger) Predicate(p Predicate) string {
	strs := make([]string, len(p.Terms))
	for i, id := range p.Terms {
		strs[i] = d.Term(id)
	}
	return fmt.Sprintf("%s(%s)", d.Str(p.Name), strings.Join(strs, ", "))
}

// Term formats a term using the symbol table to resolve String symbols.
func (d SymbolDebugger) Term(t Term) string {
	switch v := t.(type) {
	case String:
		return fmt.Sprintf("\"%s\"", d.Str(v))
	case Variable:
		return "$" + d.Var(v)
	case Set:
		// Format set elements using the debugger and use curly braces
		elements := make([]string, 0, v.Size())
		for _, elem := range set.Sorted(v.Iter()) {
			elements = append(elements, d.Term(elem))
		}
		// Empty sets use {,} format per Biscuit spec
		if len(elements) == 0 {
			return "{,}"
		}
		return "{" + strings.Join(elements, ", ") + "}"
	default:
		return fmt.Sprintf("%v", t)
	}
}

func (d SymbolDebugger) Rule(r Rule) string {
	head := d.Predicate(r.Head)
	preds := make([]string, len(r.Body))
	for i, p := range r.Body {
		preds[i] = d.Predicate(p)
	}
	expressions := make([]string, len(r.Expressions))
	for i, e := range r.Expressions {
		expressions[i] = d.Expression(e)
	}

	var expressionsStart string
	if len(preds) > 0 && len(expressions) > 0 {
		expressionsStart = ", "
	}

	return fmt.Sprintf("%s <- %s%s%s", head, strings.Join(preds, ", "), expressionsStart, strings.Join(expressions, ", "))
}

func (d SymbolDebugger) CheckQuery(r Rule) string {
	preds := make([]string, len(r.Body))
	for i, p := range r.Body {
		preds[i] = d.Predicate(p)
	}
	expressions := make([]string, len(r.Expressions))
	for i, e := range r.Expressions {
		expressions[i] = d.Expression(e)
	}

	var expressionsStart string
	if len(preds) > 0 && len(expressions) > 0 {
		expressionsStart = ", "
	}

	query := fmt.Sprintf("%s%s%s", strings.Join(preds, ", "), expressionsStart, strings.Join(expressions, ", "))

	// Add scope annotations if present
	if len(r.Scopes) > 0 {
		scopeStrs := make([]string, 0, len(r.Scopes))
		for _, scope := range r.Scopes {
			scopeStrs = append(scopeStrs, d.Scope(scope))
		}
		query += " " + strings.Join(scopeStrs, ", ")
	}

	return query
}

// Scope formats a scope annotation
func (d SymbolDebugger) Scope(s Scope) string {
	switch s.Type {
	case AuthorityScopeType:
		return "trusting authority"
	case PreviousScopeType:
		return "trusting previous"
	case PublicKeyScopeType:
		if d.PublicKeyTable != nil && int(s.PublicKeyTableIndex) < len(*d.PublicKeyTable) {
			pk := (*d.PublicKeyTable)[s.PublicKeyTableIndex]
			return fmt.Sprintf("trusting %s", d.PublicKey(pk))
		}
		return fmt.Sprintf("trusting <key#%d>", s.PublicKeyTableIndex)
	default:
		return fmt.Sprintf("trusting <unknown:%d>", s.Type)
	}
}

// PublicKey formats a public key
func (d SymbolDebugger) PublicKey(pk PublicKey) string {
	alg := "unknown"
	switch pk.Algorithm {
	case pb.PublicKey_Ed25519:
		alg = "ed25519"
	case pb.PublicKey_SECP256R1:
		alg = "secp256r1"
	}
	return fmt.Sprintf("%s/%x", alg, pk.Key)
}

func (d SymbolDebugger) Expression(e Expression) string {
	return e.Print(d.SymbolTable)
}

func (d SymbolDebugger) Check(c Check) string {
	queries := make([]string, len(c.Queries))
	for i, q := range c.Queries {
		queries[i] = d.CheckQuery(q)
	}
	var checkSyntax string
	switch c.Kind {
	case CheckAll:
		checkSyntax = "check all"
	case CheckReject:
		checkSyntax = "reject if"
	case CheckOne:
		fallthrough
	default:
		checkSyntax = "check if"
	}
	return fmt.Sprintf("%s %s", checkSyntax, strings.Join(queries, " or "))
}

func (d SymbolDebugger) World(w *World) string {
	facts := make([]string, 0, w.Facts.Count())
	for f := range w.Facts.AllFacts() {
		facts = append(facts, d.Predicate(f.Predicate))
	}
	rules := make([]string, 0, len(w.Rules))
	for r := range w.Rules.AllRules() {
		rules = append(rules, d.Rule(r))
	}

	sort.Strings(facts)
	sort.Strings(rules)
	return fmt.Sprintf("World {{\n\tfacts: %v\n\trules: %v\n}}", facts, rules)
}

func (d SymbolDebugger) FactSet(s FactSet) string {
	strs := make([]string, 0, s.Count())
	for fact := range s.AllFacts() {
		strs = append(strs, d.Predicate(fact.Predicate))
	}
	return fmt.Sprintf("%v", strs)
}

func (d SymbolDebugger) Facts(s []Fact) string {
	strs := make([]string, 0, len(s))
	for _, fact := range s {
		strs = append(strs, d.Predicate(fact.Predicate))
	}
	return fmt.Sprintf("%v", strs)
}
