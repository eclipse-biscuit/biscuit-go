package datalog

import (
	"bytes"
	"github.com/eclipse-biscuit/biscuit-go/v2/pb"
)

type PublicKey struct {
	Key       []byte
	Algorithm pb.PublicKey_Algorithm
}

func (pk *PublicKey) Equal(other PublicKey) bool {
	return pk.Algorithm == other.Algorithm && bytes.Equal(pk.Key, other.Key)
}

type PublicKeyTable []PublicKey

func NewPublicKeyTable() *PublicKeyTable {
	result := make(PublicKeyTable, 0)
	return &result
}

func (t *PublicKeyTable) Clone() *PublicKeyTable {
	if t == nil {
		return nil
	}
	result := make(PublicKeyTable, len(*t))
	copy(result, *t)
	return &result
}

func (t *PublicKeyTable) Insert(newKey PublicKey) uint64 {
	for index, existingKey := range *t {
		if existingKey.Equal(newKey) {
			return uint64(index)
		}
	}

	*t = append(*t, newKey)
	return uint64(len(*t) - 1)
}

func (t *PublicKeyTable) Extend(other *PublicKeyTable) {
	for _, otherPublicKey := range *other {
		t.Insert(otherPublicKey)
	}
}

func (t *PublicKeyTable) Index(pk *PublicKey) (int, bool) {
	for i, existingKey := range *t {
		if existingKey.Equal(*pk) {
			return i, true
		}
	}
	return -1, false
}

// SplitOff returns a newly allocated slice containing the elements in the range
// [at, len). After the call, the receiver will be left containing
// the elements [0, at) with its previous capacity unchanged.
func (t *PublicKeyTable) SplitOff(at int) *PublicKeyTable {
	if at > len(*t) {
		panic("split index out of bound")
	}

	newTable := make(PublicKeyTable, len(*t)-at)
	copy(newTable, (*t)[at:])

	*t = (*t)[:at]

	return &newTable
}
