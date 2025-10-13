// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package biscuit

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"

	//"crypto/sha256"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"

	"github.com/eclipse-biscuit/biscuit-go/v2/datalog"
	"github.com/eclipse-biscuit/biscuit-go/v2/pb"

	//"github.com/eclipse-biscuit/biscuit-go/sig"
	"google.golang.org/protobuf/proto"
)

// Biscuit represents a valid Biscuit token
// It contains multiple `Block` elements, the associated symbol table,
// and a serialized version of this data
type Biscuit struct {
	authority *Block
	blocks    []*Block
	symbols   *datalog.SymbolTable
	container *pb.Biscuit
}

var (
	// ErrSymbolTableOverlap is returned when multiple blocks declare the same symbols
	ErrSymbolTableOverlap = errors.New("biscuit: symbol table overlap")
	// ErrInvalidAuthorityIndex occurs when an authority block index is not 0
	ErrInvalidAuthorityIndex = errors.New("biscuit: invalid authority index")
	// ErrInvalidAuthorityFact occurs when an authority fact is an ambient fact
	ErrInvalidAuthorityFact = errors.New("biscuit: invalid authority fact")
	// ErrInvalidBlockFact occurs when a block fact provides an authority or ambient fact
	ErrInvalidBlockFact = errors.New("biscuit: invalid block fact")
	// ErrInvalidBlockRule occurs when a block rule generate an authority or ambient fact
	ErrInvalidBlockRule = errors.New("biscuit: invalid block rule")
	// ErrEmptyKeys is returned when verifying a biscuit having no keys
	ErrEmptyKeys = errors.New("biscuit: empty keys")
	// ErrNoPublicKeyAvailable is returned when no public root key is available to verify the
	// signatures on a biscuit's blocks.
	ErrNoPublicKeyAvailable = errors.New("biscuit: no public key available")
	// ErrUnknownPublicKey is returned when verifying a biscuit with the wrong public key
	ErrUnknownPublicKey = errors.New("biscuit: unknown public key")

	ErrInvalidSignature = errors.New("biscuit: invalid signature")

	ErrInvalidSignatureSize = errors.New("biscuit: invalid signature size")

	ErrInvalidKeySize = errors.New("biscuit: invalid key size")

	UnsupportedAlgorithm = errors.New("biscuit: unsupported signature algorithm")
)

type biscuitOptions struct {
	rng       io.Reader
	rootKeyID *uint32
}

type biscuitOption interface {
	applyToBiscuit(*biscuitOptions) error
}

func newBiscuit(root ed25519.PrivateKey, baseSymbols *datalog.SymbolTable, authority *Block, opts ...biscuitOption) (*Biscuit, error) {
	options := biscuitOptions{
		rng: rand.Reader,
	}
	for _, opt := range opts {
		if err := opt.applyToBiscuit(&options); err != nil {
			return nil, err
		}
	}

	symbols := baseSymbols.Clone()

	if !symbols.IsDisjoint(authority.symbols) {
		return nil, ErrSymbolTableOverlap
	}

	symbols.Extend(authority.symbols)

	nextPublicKey, nextPrivateKey, _ := ed25519.GenerateKey(options.rng)

	protoAuthority, err := tokenBlockToProtoBlock(authority)
	if err != nil {
		return nil, err
	}
	marshalledAuthority, err := proto.Marshal(protoAuthority)
	if err != nil {
		return nil, err
	}

	algorithm := pb.PublicKey_Ed25519
	toSignAlgorithm := make([]byte, 4)
	binary.LittleEndian.PutUint32(toSignAlgorithm[0:], uint32(pb.PublicKey_Ed25519))
	toSign := append(marshalledAuthority[:], toSignAlgorithm...)
	toSign = append(toSign, nextPublicKey[:]...)

	signature := ed25519.Sign(root, toSign)
	nextKey := &pb.PublicKey{
		Algorithm: &algorithm,
		Key:       nextPublicKey,
	}

	signedBlock := &pb.SignedBlock{
		Block:     marshalledAuthority,
		NextKey:   nextKey,
		Signature: signature,
	}

	proof := &pb.Proof{
		Content: &pb.Proof_NextSecret{
			NextSecret: nextPrivateKey.Seed(),
		},
	}

	container := &pb.Biscuit{
		RootKeyId: options.rootKeyID,
		Authority: signedBlock,
		Proof:     proof,
	}

	return &Biscuit{
		authority: authority,
		symbols:   symbols,
		container: container,
	}, nil
}

func New(rng io.Reader, root ed25519.PrivateKey, baseSymbols *datalog.SymbolTable, authority *Block) (*Biscuit, error) {
	var opts []biscuitOption
	if rng != nil {
		opts = []biscuitOption{WithRNG(rng)}
	}
	return newBiscuit(root, baseSymbols, authority, opts...)
}

func (b *Biscuit) CreateBlock() BlockBuilder {
	return NewBlockBuilder(b.symbols.Clone())
}

func (b *Biscuit) Append(rng io.Reader, block *Block) (*Biscuit, error) {
	if b.container == nil {
		return nil, errors.New("biscuit: append failed, token is sealed")
	}

	privateKey := b.container.Proof.GetNextSecret()
	if privateKey == nil {
		return nil, errors.New("biscuit: append failed, token is sealed")
	}

	if len(privateKey) != 32 {
		return nil, ErrInvalidKeySize
	}

	privateKey = ed25519.NewKeyFromSeed(privateKey)

	if !b.symbols.IsDisjoint(block.symbols) {
		return nil, ErrSymbolTableOverlap
	}

	// clone biscuit fields and append new block
	authority := new(Block)
	*authority = *b.authority

	blocks := make([]*Block, len(b.blocks)+1)
	for i, oldBlock := range b.blocks {
		blocks[i] = new(Block)
		*blocks[i] = *oldBlock
	}
	blocks[len(b.blocks)] = block

	symbols := b.symbols.Clone()
	symbols.Extend(block.symbols)

	nextPublicKey, nextPrivateKey, _ := ed25519.GenerateKey(rng)

	// serialize and sign the new block
	protoBlock, err := tokenBlockToProtoBlock(block)
	if err != nil {
		return nil, err
	}
	marshalledBlock, err := proto.Marshal(protoBlock)
	if err != nil {
		return nil, err
	}

	algorithm := pb.PublicKey_Ed25519
	toSignAlgorithm := make([]byte, 4)
	binary.LittleEndian.PutUint32(toSignAlgorithm[0:], uint32(pb.PublicKey_Ed25519))
	toSign := append(marshalledBlock[:], toSignAlgorithm...)
	toSign = append(toSign, nextPublicKey[:]...)

	signature := ed25519.Sign(privateKey, toSign)
	nextKey := &pb.PublicKey{
		Algorithm: &algorithm,
		Key:       nextPublicKey,
	}

	signedBlock := &pb.SignedBlock{
		Block:     marshalledBlock,
		NextKey:   nextKey,
		Signature: signature,
	}

	proof := &pb.Proof{
		Content: &pb.Proof_NextSecret{
			NextSecret: nextPrivateKey.Seed(),
		},
	}

	// clone container and append new marshalled block and public key
	container := &pb.Biscuit{
		Authority: b.container.Authority,
		Blocks:    append([]*pb.SignedBlock{}, b.container.Blocks...),
		Proof:     proof,
	}

	container.Blocks = append(container.Blocks, signedBlock)

	return &Biscuit{
		authority: authority,
		blocks:    blocks,
		symbols:   symbols,
		container: container,
	}, nil
}

func (b *Biscuit) Seal(rng io.Reader) (*Biscuit, error) {
	if b.container == nil {
		return nil, errors.New("biscuit: token is already sealed")
	}

	privateKey := b.container.Proof.GetNextSecret()
	if privateKey == nil {
		return nil, errors.New("biscuit: token is already sealed")
	}

	if len(privateKey) != 32 {
		return nil, ErrInvalidKeySize
	}

	privateKey = ed25519.NewKeyFromSeed(privateKey)

	// clone biscuit fields and append new block
	authority := new(Block)
	*authority = *b.authority

	blocks := make([]*Block, len(b.blocks))
	for i, oldBlock := range b.blocks {
		blocks[i] = new(Block)
		*blocks[i] = *oldBlock
	}

	var lastBlock *pb.SignedBlock
	if len(b.blocks) == 0 {
		lastBlock = b.container.Authority
	} else {
		lastBlock = b.container.Blocks[len(b.blocks)-1]
	}

	toSignAlgorithm := make([]byte, 4)
	binary.LittleEndian.PutUint32(toSignAlgorithm[0:], uint32(lastBlock.NextKey.Algorithm.Number()))
	toSign := append(lastBlock.Block[:], toSignAlgorithm...)
	toSign = append(toSign, lastBlock.NextKey.Key[:]...)
	toSign = append(toSign, lastBlock.Signature[:]...)

	signature := ed25519.Sign(privateKey, toSign)

	proof := &pb.Proof{
		Content: &pb.Proof_FinalSignature{
			FinalSignature: signature,
		},
	}

	// clone container and append new marshalled block and public key
	container := &pb.Biscuit{
		Authority: b.container.Authority,
		Blocks:    append([]*pb.SignedBlock{}, b.container.Blocks...),
		Proof:     proof,
	}

	symbols := b.symbols.Clone()

	return &Biscuit{
		authority: authority,
		blocks:    blocks,
		symbols:   symbols,
		container: container,
	}, nil
}

type (
	// A PublickKeyByIDProjection inspects an optional ID for a public key and returns the
	// corresponding public key, if any. If it doesn't recognize the ID or can't find the public
	// key, or no ID is supplied and there is no default public key available, it should return an
	// error satisfying errors.Is(err, ErrNoPublicKeyAvailable).
	PublickKeyByIDProjection func(*uint32) (ed25519.PublicKey, error)
)

// WithSingularRootPublicKey supplies one public key to use as the root key with which to verify the
// signatures on a biscuit's blocks.
func WithSingularRootPublicKey(key ed25519.PublicKey) PublickKeyByIDProjection {
	return func(*uint32) (ed25519.PublicKey, error) {
		return key, nil
	}
}

// WithRootPublicKeys supplies a mapping to public keys from their corresponding IDs, used to select
// which public key to use to verify the signatures on a biscuit's blocks based on the key ID
// embedded within the biscuit when it was created. If the biscuit has no key ID available, this
// function selects the optional default key instead. If no public key is available—whether for the
// biscuit's embedded key ID or a default key when no such ID is present—it returns
// [ErrNoPublicKeyAvailable].
func WithRootPublicKeys(keysByID map[uint32]ed25519.PublicKey, defaultKey *ed25519.PublicKey) PublickKeyByIDProjection {
	return func(id *uint32) (ed25519.PublicKey, error) {
		if id == nil {
			if defaultKey != nil {
				return *defaultKey, nil
			}
		} else if key, ok := keysByID[*id]; ok {
			return key, nil
		}
		return nil, ErrNoPublicKeyAvailable
	}
}

func (b *Biscuit) authorizerFor(root ed25519.PublicKey, opts ...AuthorizerOption) (Authorizer, error) {
	currentKey := root

	// for now we only support Ed25519
	if *b.container.Authority.NextKey.Algorithm != pb.PublicKey_Ed25519 {
		return nil, UnsupportedAlgorithm
	}

	algorithm := make([]byte, 4)
	binary.LittleEndian.PutUint32(algorithm[0:], uint32(b.container.Authority.NextKey.Algorithm.Number()))

	toVerify := append(b.container.Authority.Block[:], algorithm...)
	toVerify = append(toVerify, b.container.Authority.NextKey.Key[:]...)

	if ok := ed25519.Verify(currentKey, toVerify, b.container.Authority.Signature); !ok {
		return nil, ErrInvalidSignature
	}

	currentKey = b.container.Authority.NextKey.Key
	if len(currentKey) != 32 {
		return nil, ErrInvalidKeySize
	}

	for _, block := range b.container.Blocks {
		if *block.NextKey.Algorithm != pb.PublicKey_Ed25519 {
			return nil, UnsupportedAlgorithm
		}

		algorithm := make([]byte, 4)
		binary.LittleEndian.PutUint32(algorithm[0:], uint32(block.NextKey.Algorithm.Number()))
		toVerify := append(block.Block[:], algorithm...)
		toVerify = append(toVerify, block.NextKey.Key[:]...)

		if ok := ed25519.Verify(currentKey, toVerify, block.Signature); !ok {
			return nil, ErrInvalidSignature
		}

		currentKey = block.NextKey.Key
		if len(currentKey) != 32 {
			return nil, ErrInvalidKeySize
		}
	}

	switch {
	case b.container.Proof.GetNextSecret() != nil:
		{
			privateKey := b.container.Proof.GetNextSecret()
			if privateKey == nil {
				return nil, errors.New("biscuit: sealed token verification not implemented")
			}

			publicKey := ed25519.NewKeyFromSeed(privateKey).Public()
			if !bytes.Equal(currentKey, publicKey.(ed25519.PublicKey)) {
				return nil, errors.New("biscuit: invalid last signature")
			}
		}
	case b.container.Proof.GetFinalSignature() != nil:
		{
			signature := b.container.Proof.GetFinalSignature()
			var lastBlock *pb.SignedBlock
			if len(b.blocks) == 0 {
				lastBlock = b.container.Authority
			} else {
				lastBlock = b.container.Blocks[len(b.blocks)-1]
			}

			algorithm := make([]byte, 4)
			binary.LittleEndian.PutUint32(algorithm[0:], uint32(lastBlock.NextKey.Algorithm.Number()))
			toVerify := append(lastBlock.Block[:], algorithm...)
			toVerify = append(toVerify, lastBlock.NextKey.Key[:]...)
			toVerify = append(toVerify, lastBlock.Signature[:]...)

			if ok := ed25519.Verify(currentKey, toVerify, signature); !ok {
				return nil, errors.New("biscuit: invalid last signature")
			}
		}
	default:
		return nil, errors.New("biscuit: cannot find proof")
	}

	return NewVerifier(b, opts...)
}

// AuthorizerFor selects from the supplied source a root public key to use to verify the signatures
// on the biscuit's blocks, returning an error satisfying errors.Is(err, ErrNoPublicKeyAvailable) if
// no such public key is available. If the signatures are valid, it creates an [Authorizer], which
// can then test the authorization policies and accept or refuse the request.
func (b *Biscuit) AuthorizerFor(keySource PublickKeyByIDProjection, opts ...AuthorizerOption) (Authorizer, error) {
	if keySource == nil {
		return nil, errors.New("root public key source must not be nil")
	}
	rootPublicKey, err := keySource(b.RootKeyID())
	if err != nil {
		return nil, fmt.Errorf("choosing root public key: %w", err)
	}
	if len(rootPublicKey) == 0 {
		return nil, ErrNoPublicKeyAvailable
	}
	return b.authorizerFor(rootPublicKey, opts...)
}

// TODO: Add "Deprecated" note to the "(*Biscuit).Authorizer" method, recommending use of
// "(*Biscuit).AuthorizerFor" instead. Wait until after we release the module with the latter
// available, per https://go.dev/wiki/Deprecated.

// Authorizer checks the signature and creates an [Authorizer]. The Authorizer can then test the
// authorizaion policies and accept or refuse the request.
func (b *Biscuit) Authorizer(root ed25519.PublicKey, opts ...AuthorizerOption) (Authorizer, error) {
	return b.authorizerFor(root)
}

func (b *Biscuit) Checks() [][]datalog.Check {
	result := make([][]datalog.Check, 0, len(b.blocks)+1)
	result = append(result, b.authority.checks)
	for _, block := range b.blocks {
		result = append(result, block.checks)
	}
	return result
}

func (b *Biscuit) GetContext() string {
	if b == nil || b.authority == nil {
		return ""
	}

	return b.authority.context
}

func (b *Biscuit) Serialize() ([]byte, error) {
	return proto.Marshal(b.container)
}

var ErrFactNotFound = errors.New("biscuit: fact not found")

// GetBlockID returns the first block index containing a fact
// starting from the authority block and then each block in the order they were added.
// ErrFactNotFound is returned when no block contains the fact.
func (b *Biscuit) GetBlockID(fact Fact) (int, error) {
	// don't store symbols from searched fact in the verifier table
	symbols := b.symbols.Clone()
	datalogFact := fact.Predicate.convert(symbols)

	for _, f := range *b.authority.facts {
		if f.Equal(datalogFact) {
			return 0, nil
		}
	}

	for i, b := range b.blocks {
		for _, f := range *b.facts {
			if f.Equal(datalogFact) {
				return i + 1, nil
			}
		}
	}

	return 0, ErrFactNotFound
}

/*
// SHA256Sum returns a hash of `count` biscuit blocks + the authority block
// along with their respective keys.
func (b *Biscuit) SHA256Sum(count int) ([]byte, error) {
	if count < 0 {
		return nil, fmt.Errorf("biscuit: invalid count,  %d < 0 ", count)
	}
	if g, w := count, len(b.container.Blocks); g > w {
		return nil, fmt.Errorf("biscuit: invalid count,  %d > %d", g, w)
	}

	h := sha256.New()
	// write the authority block and the root key
	if _, err := h.Write(b.container.Authority); err != nil {
		return nil, err
	}
	if _, err := h.Write(b.container.Keys[0]); err != nil {
		return nil, err
	}

	for _, block := range b.container.Blocks[:count] {
		if _, err := h.Write(block); err != nil {
			return nil, err
		}
	}
	for _, key := range b.container.Keys[:count+1] { // +1 to skip the root key
		if _, err := h.Write(key); err != nil {
			return nil, err
		}
	}

	return h.Sum(nil), nil
}*/

func (b *Biscuit) BlockCount() int {
	return len(b.container.Blocks)
}

func (b *Biscuit) RootKeyID() *uint32 {
	return b.container.RootKeyId
}

func (b *Biscuit) String() string {
	blocks := make([]string, len(b.blocks))
	for i, block := range b.blocks {
		blocks[i] = block.String(b.symbols)
	}

	return fmt.Sprintf(`
Biscuit {
	symbols: %+q
	authority: %s
	blocks: %v
}`,
		*b.symbols,
		b.authority.String(b.symbols),
		blocks,
	)
}

func (b *Biscuit) Code() []string {
	blocks := make([]string, len(b.blocks))
	for i, block := range b.blocks {
		blocks[i] = block.Code(b.symbols)
	}
	return blocks
}

/*
func (b *Biscuit) checkRootKey(root ed25519.PublicKey) error {
	if len(b.container.Keys) == 0 {
		return ErrEmptyKeys
	}
	if !bytes.Equal(b.container.Keys[0], root.Bytes()) {
		return ErrUnknownPublicKey
	}

	return nil
}*/

func (b *Biscuit) generateWorld(symbols *datalog.SymbolTable) (*datalog.World, error) {
	world := datalog.NewWorld()

	for _, fact := range *b.authority.facts {
		world.AddFact(fact)
	}

	for _, rule := range b.authority.rules {
		world.AddRule(rule)
	}

	for _, block := range b.blocks {
		for _, fact := range *block.facts {
			world.AddFact(fact)
		}

		for _, rule := range block.rules {
			world.AddRule(rule)
		}
	}

	if err := world.Run(symbols); err != nil {
		return nil, err
	}

	return world, nil
}

func (b *Biscuit) RevocationIds() [][]byte {
	result := make([][]byte, 0, len(b.blocks)+1)
	result = append(result, b.container.Authority.Signature)
	for _, block := range b.container.Blocks {
		result = append(result, block.Signature)
	}
	return result
}
