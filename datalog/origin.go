package datalog

import (
	"cmp"
	"fmt"
	"iter"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/eclipse-biscuit/biscuit-go/v2/internal/set"
)

const AuthorizerBlockID uint64 = math.MaxUint64

type Origin struct {
	inner *set.HashSet[BlockID]
}

// NewOrigin creates an [[Origin]] with one or more block IDs.
func NewOrigin(firstBlockID uint64, moreBlockIDs ...uint64) *Origin {
	setBlockIDs := set.NewHashSet(BlockID(firstBlockID))
	for _, v := range moreBlockIDs {
		setBlockIDs.Insert(BlockID(v))
	}

	return &Origin{
		inner: setBlockIDs,
	}
}

// NewOriginFromString creates an [[Origin]] from an encoded string.
// Encoded strings are used by [[FactSet]] to store origins as string keys.
func NewOriginFromString(encodedBlockIDs string) (*Origin, error) {
	// Handle empty string (no block IDs)
	if encodedBlockIDs == "" {
		return nil, fmt.Errorf("empty encoded block ids")
	}

	parts := strings.Split(encodedBlockIDs, ",")
	setBlockIDs := set.NewHashSet[BlockID]()
	for _, part := range parts {
		num, err := strconv.ParseUint(part, 36, 64)
		if err != nil {
			return nil, err
		}
		_ = setBlockIDs.Insert(BlockID(num))
	}
	return &Origin{inner: setBlockIDs}, nil
}

func (o *Origin) Contains(id BlockID) bool {
	return o.inner.Contains(id)
}

func (o *Origin) InsertIDs(blockIDs ...uint64) {
	for _, v := range blockIDs {
		o.inner.Insert(BlockID(v))
	}
}

func (o *Origin) InsertIDSlice(blockIDs []BlockID) {
	otherSet := set.NewHashSet[BlockID](blockIDs...)
	o.inner = o.inner.Union(otherSet)
}

func (o *Origin) InsertOrigin(other *Origin) {
	o.inner = o.inner.Union(other.inner)
}

func (o *Origin) clone() *Origin {
	return &Origin{
		inner: o.inner.Clone(),
	}
}

func (o *Origin) With(blockIDs ...uint64) *Origin {
	result := o.clone()
	for _, blockID := range blockIDs {
		result.InsertIDs(blockID)
	}
	return result
}

func (o *Origin) IsSuperSet(other *Origin) bool {
	return o.inner.IsSuperSet(other.inner)
}

func (o *Origin) EncodeToString() string {
	var b strings.Builder

	i := 0
	for _, id := range set.Sorted(o.inner.Iter()) {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.FormatUint(uint64(id), 36))
		i += 1
	}

	return b.String()
}

// BlockIDs returns an iterator that yields sorted block IDs (as uint64).
// Note that we use custom logic for sorting BlockIDs.
func (o *Origin) BlockIDs() iter.Seq[uint64] {
	// Yield each block ID as a uint64.
	return func(yield func(uint64) bool) {
		for _, blockID := range set.Sorted(o.inner.Iter()) {
			if !yield(uint64(blockID)) {
				return
			}
		}
	}
}

// Compare allows us to sort [Origin]s (using our custom sorted block IDs).
func (o *Origin) Compare(o2 Origin) int {
	sl1 := set.Sorted(o.inner.Iter())
	sl2 := set.Sorted(o2.inner.Iter())

	minLen := min(len(sl1), len(sl2))
	for i := 0; i < minLen; i++ {
		if x := sl1[i].Compare(sl2[i]); x != 0 {
			return x
		}
	}

	// If all compared elements are equal, shorter origin comes first
	return cmp.Compare(len(sl1), len(sl2))
}

var _ set.Ordered[Origin] = (*Origin)(nil)

type TrustedOrigin struct {
	*Origin
}

func NewTrustedOrigin() *TrustedOrigin {
	return &TrustedOrigin{NewOrigin(0, AuthorizerBlockID)}
}

func NewTrustedOriginFromString(encodedBlockIDs string) (*TrustedOrigin, error) {
	origin, err := NewOriginFromString(encodedBlockIDs)
	if err != nil {
		return nil, err
	}
	return &TrustedOrigin{origin}, nil
}

func (to *TrustedOrigin) With(blockIDs ...uint64) *TrustedOrigin {
	return &TrustedOrigin{
		Origin: to.Origin.With(blockIDs...),
	}
}

type SignatureRegistry map[uint64]*set.HashSet[BlockID]

func (sr *SignatureRegistry) Insert(publicKeyTableIndex uint64, newBlockIDs ...BlockID) {
	if oldBlockIDs, exists := (*sr)[publicKeyTableIndex]; exists {
		combinedBlockIDs := oldBlockIDs.Union(set.NewHashSet(newBlockIDs...))
		(*sr)[publicKeyTableIndex] = combinedBlockIDs
	} else {
		(*sr)[publicKeyTableIndex] = set.NewHashSet(newBlockIDs...)
	}
}

func (sr *SignatureRegistry) Clone() *SignatureRegistry {
	result := make(SignatureRegistry, len(*sr))
	for k, v := range *sr {
		newSet := set.NewHashSet[BlockID]()
		for id := range v.Iter() {
			newSet.Insert(id)
		}
		result[k] = newSet
	}
	return &result
}

func NewTrustedOriginFromScopes(
	blockScopes []Scope,
	ruleScopes []Scope,
	currentBlockID uint64,
	signatureRegistry SignatureRegistry,
) *TrustedOrigin {
	origin := NewOrigin(AuthorizerBlockID, currentBlockID)

	scopes := ruleScopes
	if len(scopes) == 0 {
		scopes = blockScopes
	}

	if len(scopes) == 0 {
		return NewTrustedOrigin().With(currentBlockID)
	}

	for _, scope := range scopes {
		switch scope.Type {
		case AuthorityScopeType:
			origin.InsertIDs(0)
		case PreviousScopeType:
			// The `previous` scope includes all blocks that executed before the current block.
			// When used in the authorizer, `previous` is ignored per the Biscuit specification.
			// When used in a block, it includes all blocks from authority up to (but not including) the current block.
			if currentBlockID != AuthorizerBlockID {
				for i := range currentBlockID {
					origin.InsertIDs(i)
				}
			}
			// Note: When currentBlockID == AuthorizerBlockID, previous scope is ignored (no blocks added)
		case PublicKeyScopeType:
			index := scope.PublicKeyTableIndex
			if blockIDs, exists := signatureRegistry[index]; exists {
				origin.InsertIDSlice(slices.Collect(blockIDs.Iter()))
			}
		}
	}

	return &TrustedOrigin{Origin: origin}
}
