package set

type Ordered[T any] interface {
	Compare(other T) int
}

type Equality[T any] interface {
	Equal(other T) bool
}

type Hashable[T any] interface {
	Hash(builder *HashBuilder) *HashBuilder
}
