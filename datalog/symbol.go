// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package datalog

import (
	"crypto/ed25519"
	"fmt"
	"sort"
	"strings"
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

type SymbolTable struct {
	Symbols    []string
	PublicKeys []ed25519.PublicKey
}

func (t *SymbolTable) Insert(s string) String {
	for i, v := range DEFAULT_SYMBOLS {
		if string(v) == s {
			return String(i)
		}
	}

	for i, v := range t.Symbols {
		if v == s {
			return String(OFFSET + i)
		}
	}
	t.Symbols = append(t.Symbols, s)

	return String(OFFSET + len(t.Symbols) - 1)
}

func (t *SymbolTable) Sym(s string) Term {
	for i, v := range DEFAULT_SYMBOLS {
		if string(v) == s {
			return String(i)
		}
	}

	for i, v := range t.Symbols {
		if v == s {
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

	for i, v := range t.Symbols {
		if v == s {
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
	if int(sym)-1024 > len(t.Symbols)-1 {
		return fmt.Sprintf("<invalid symbol %d>", sym)
	}
	return t.Symbols[int(sym)-1024]
}

func (t *SymbolTable) Var(v Variable) string {
	if int(v) < 1024 {
		if int(v) > len(DEFAULT_SYMBOLS)-1 {
			return fmt.Sprintf("<invalid variable %d>", v)
		} else {
			return DEFAULT_SYMBOLS[int(v)]
		}
	}
	if int(v)-1024 > len(t.Symbols)-1 {
		return fmt.Sprintf("<invalid variable %d>", v)
	}
	return t.Symbols[int(v)-1024]
}

func (t *SymbolTable) Clone() *SymbolTable {
	newTable := *t
	return &newTable
}

// SplitOff returns a newly allocated slice containing the elements in the range
// [at, len). After the call, the receiver will be left containing
// the elements [0, at) with its previous capacity unchanged.
func (t *SymbolTable) SplitOff(at int) *SymbolTable {
	if at > len(t.Symbols) {
		panic("split index out of bound")
	}

	new := SymbolTable{
		Symbols:    make([]string, len(t.Symbols)-at),
		PublicKeys: t.PublicKeys,
	}
	copy(new.Symbols, t.Symbols[at:])

	t.Symbols = t.Symbols[:at]

	return &new
}

func (t *SymbolTable) Len() int {
	return len(t.Symbols)
}

// IsDisjoint returns true if receiver has no elements in common with other.
// This is equivalent to checking for an empty intersection.
func (t *SymbolTable) IsDisjoint(other *SymbolTable) bool {
	m := make(map[string]struct{}, len(t.Symbols))
	for _, s := range t.Symbols {
		m[s] = struct{}{}
	}

	for _, os := range other.Symbols {
		if _, ok := m[os]; ok {
			return false
		}
	}

	return true
}

// Extend insert symbols from the given SymbolTable in the receiving one
// excluding any Symbols already existing
func (t *SymbolTable) Extend(other *SymbolTable) {
	for _, s := range other.Symbols {
		t.Insert(s)
	}
}

type SymbolDebugger struct {
	*SymbolTable
}

func (d SymbolDebugger) Predicate(p Predicate) string {
	strs := make([]string, len(p.Terms))
	for i, id := range p.Terms {
		var s string
		if sym, ok := id.(String); ok {
			s = "\"" + d.Str(sym) + "\""
		} else if variable, ok := id.(Variable); ok {
			s = "$" + d.Var(variable)
		} else {
			s = fmt.Sprintf("%v", id)
		}
		strs[i] = s
	}
	return fmt.Sprintf("%s(%s)", d.Str(p.Name), strings.Join(strs, ", "))
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

	return fmt.Sprintf("%s%s%s", strings.Join(preds, ", "), expressionsStart, strings.Join(expressions, ", "))
}

func (d SymbolDebugger) Expression(e Expression) string {
	return e.Print(d.SymbolTable)
}

func (d SymbolDebugger) Check(c Check) string {
	queries := make([]string, len(c.Queries))
	for i, q := range c.Queries {
		queries[i] = d.CheckQuery(q)
	}
	return fmt.Sprintf("check if %s", strings.Join(queries, " or "))
}

func (d SymbolDebugger) World(w *World) string {
	facts := make([]string, len(*w.facts))
	for i, f := range *w.facts {
		facts[i] = d.Predicate(f.Predicate)
	}
	rules := make([]string, len(w.rules))
	for i, r := range w.rules {
		rules[i] = d.Rule(r)
	}

	sort.Strings(facts)
	sort.Strings(rules)
	return fmt.Sprintf("World {{\n\tfacts: %v\n\trules: %v\n}}", facts, rules)
}

func (d SymbolDebugger) FactSet(s *FactSet) string {
	strs := make([]string, len(*s))
	for i, f := range *s {
		strs[i] = d.Predicate(f.Predicate)
	}
	return fmt.Sprintf("%v", strs)
}
