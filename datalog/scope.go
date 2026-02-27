package datalog

import (
	"cmp"

	"github.com/eclipse-biscuit/biscuit-go/v2/internal/set"
)

type ScopeType uint

const (
	AuthorityScopeType ScopeType = iota
	PreviousScopeType
	PublicKeyScopeType
)

type Scope struct {
	Type                ScopeType
	PublicKeyTableIndex uint64
}

func (s Scope) Compare(other Scope) int {
	if x := cmp.Compare(s.Type, other.Type); x != 0 {
		return x
	}
	return cmp.Compare(s.PublicKeyTableIndex, other.PublicKeyTableIndex)
}

func (s Scope) Equal(other Scope) bool {
	return s.Compare(other) == 0
}

func (s Scope) Hash(builder *set.HashBuilder) *set.HashBuilder {
	return builder.
		Uint64(uint64(s.Type)).
		Uint64(s.PublicKeyTableIndex)
}

var _ set.Equality[Scope] = (*Scope)(nil)
var _ set.Hashable[Scope] = (*Scope)(nil)
