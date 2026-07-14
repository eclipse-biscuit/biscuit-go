package set

import (
	"iter"
	"slices"
)

type HashSetElement[T any] interface {
	Hashable[T]
	Equality[T]
}

type HashSet[T HashSetElement[T]] struct {
	buckets map[uint64][]T
	size    int
}

// NewHashSet creates a new empty HashSet
func NewHashSet[T HashSetElement[T]](values ...T) *HashSet[T] {
	result := &HashSet[T]{
		buckets: make(map[uint64][]T),
		size:    0,
	}

	for _, v := range values {
		result.Insert(v)
	}

	return result
}

func (s *HashSet[T]) Size() int {
	return s.size
}

func (s *HashSet[T]) Clone() *HashSet[T] {
	result := &HashSet[T]{
		buckets: make(map[uint64][]T),
		size:    s.size,
	}

	for h, bucket := range s.buckets {
		result.buckets[h] = append([]T{}, bucket...)
	}

	return result
}

func (s *HashSet[T]) Iter() iter.Seq[T] {
	return func(yield func(T) bool) {
		for _, bucket := range s.buckets {
			for _, v := range bucket {
				if !yield(v) {
					return
				}
			}
		}
	}
}

// Insert adds a new element to the set.
func (s *HashSet[T]) Insert(newElement T) bool {
	h := newElement.Hash(NewHashBuilder()).Build()

	var bucket []T
	var wasFound bool

	if bucket, wasFound = s.buckets[h]; !wasFound {
		bucket = make([]T, 0)
	}

	for _, existingElement := range bucket {
		if existingElement.Equal(newElement) {
			return false
		}
	}

	s.buckets[h] = append(s.buckets[h], newElement)
	s.size++

	return true
}

func (s *HashSet[T]) Remove(toRemove T) bool {
	h := toRemove.Hash(NewHashBuilder()).Build()

	if bucket, wasFound := s.buckets[h]; wasFound {
		for i, existingElement := range bucket {
			if existingElement.Equal(toRemove) {
				bucket[i] = bucket[len(bucket)-1]
				s.buckets[h] = bucket[:len(bucket)-1]
				s.size--
				return true
			}
		}
	}

	return false
}

func (s *HashSet[T]) Contains(element T) bool {
	h := element.Hash(NewHashBuilder()).Build()

	for _, existingElement := range s.buckets[h] {
		if existingElement.Equal(element) {
			return true
		}
	}

	return false
}

func (s *HashSet[T]) Intersect(other *HashSet[T]) *HashSet[T] {
	result := NewHashSet[T]()

	for leftElement := range s.Iter() {
		if other.Contains(leftElement) {
			result.Insert(leftElement)
		}
	}

	return result
}

func (s *HashSet[T]) Union(other *HashSet[T]) *HashSet[T] {
	result := s.Clone()

	for newElement := range other.Iter() {
		_ = result.Insert(newElement)
	}

	return result
}

func (s *HashSet[T]) IsSuperSet(other *HashSet[T]) bool {
	for otherElement := range other.Iter() {
		if !s.Contains(otherElement) {
			return false
		}
	}
	return true
}

func (s *HashSet[T]) ToSlice() []T {
	return slices.Collect(s.Iter())
}
