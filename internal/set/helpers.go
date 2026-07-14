package set

import (
	"cmp"
	"encoding/binary"
	"hash/maphash"
	"iter"
	"slices"
)

func CompareBool(a, b bool) int {
	if a == b {
		return 0
	}
	if !a {
		return -1
	}
	return 1
}

func defaultSortFunc[T Ordered[T]](a, b T) int {
	return a.Compare(b)
}

func Sorted[T Ordered[T]](input iter.Seq[T]) []T {
	return SortedFunc(input, defaultSortFunc)
}

func SortedFunc[T Ordered[T]](input iter.Seq[T], sortFunc func(a, b T) int) []T {
	return slices.SortedFunc(input, sortFunc)
}

func Compared[T Ordered[T]](aSeq, bSeq iter.Seq[T]) int {
	aSlc, bSlc := slices.Collect(aSeq), slices.Collect(bSeq)

	if x := cmp.Compare(len(aSlc), len(bSlc)); x != 0 {
		return x
	}

	slices.SortFunc(aSlc, defaultSortFunc)
	slices.SortFunc(bSlc, defaultSortFunc)

	for i := 0; i < len(aSlc); i++ {
		a, b := aSlc[i], bSlc[i]
		if x := a.Compare(b); x != 0 {
			return x
		}
	}

	return 0
}

func ComparedSlices[T Ordered[T]](a, b []T) int {
	if b == nil {
		return 1
	}

	if x := cmp.Compare(len(a), len(b)); x != 0 {
		return x
	}

	for i := range a {
		if x := a[i].Compare(b[i]); x != 0 {
			return x
		}
	}

	return 0
}

var globalSeed = maphash.MakeSeed()

type HashBuilder struct {
	h maphash.Hash
}

func NewHashBuilder() *HashBuilder {
	result := HashBuilder{}
	result.SetSeed(globalSeed)
	return &result
}

func (hb *HashBuilder) SetSeed(seed maphash.Seed) *HashBuilder {
	hb.h.SetSeed(seed)
	return hb
}

func (hb *HashBuilder) Uint64(n uint64) *HashBuilder {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, n)
	_, _ = hb.h.Write(buf)
	return hb
}

func (hb *HashBuilder) Int64(n int64) *HashBuilder {
	return hb.Uint64(uint64(n))
}

func (hb *HashBuilder) Bool(b bool) *HashBuilder {
	if b {
		_ = hb.h.WriteByte(byte(1))
	} else {
		_ = hb.h.WriteByte(byte(0))
	}
	return hb
}

func (hb *HashBuilder) Byte(b byte) *HashBuilder {
	_ = hb.h.WriteByte(b)
	return hb
}

func (hb *HashBuilder) Bytes(b []byte) *HashBuilder {
	_, _ = hb.h.Write(b)
	return hb
}

func (hb *HashBuilder) String(s string) *HashBuilder {
	_, _ = hb.h.WriteString(s)
	return hb
}

func (hb *HashBuilder) Hashable(item interface {
	Hash(*HashBuilder) *HashBuilder
}) *HashBuilder {
	return item.Hash(hb)
}

func (hb *HashBuilder) Build() uint64 {
	return hb.h.Sum64()
}
