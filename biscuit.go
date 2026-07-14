package biscuit

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"iter"

	"google.golang.org/protobuf/proto"

	"github.com/eclipse-biscuit/biscuit-go/v2/datalog"
	biscuitcrypto "github.com/eclipse-biscuit/biscuit-go/v2/internal/crypto"
	"github.com/eclipse-biscuit/biscuit-go/v2/pb"
)

// Biscuit represents a valid Biscuit token
// It contains multiple `Block` elements, the associated symbol table,
// and a serialized version of this data
type Biscuit struct {
	authority         *Block
	blocks            []*Block
	symbols           *datalog.SymbolTable
	publicKeys        *datalog.PublicKeyTable
	container         *pb.Biscuit
	signatureRegistry *datalog.SignatureRegistry
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
	ErrUnknownPublicKey     = errors.New("biscuit: unknown public key")
	ErrNilPublicKey         = errors.New("biscuit: nil public key")
	ErrNilExternalSignature = errors.New("biscuit: nil external signature")

	ErrInvalidSignature = errors.New("biscuit: invalid signature")

	ErrInvalidSignatureSize = errors.New("biscuit: invalid signature size")

	ErrInvalidKeySize = errors.New("biscuit: invalid key size")

	UnsupportedAlgorithm = errors.New("biscuit: unsupported signature algorithm")
)

type biscuitOptions struct {
	rng       io.Reader
	rootKeyID *uint32
}

type biscuitOption func(*biscuitOptions) error

// WithRNG supplies a random number generator as a byte stream from which to read when generating
// key pairs with which to sign signedBlocks within biscuits.
func WithRNG(r io.Reader) biscuitOption {
	return func(b *biscuitOptions) error {
		b.rng = r
		return nil
	}
}

// WithRootKeyID specifies the identifier for the root key pair used to sign a biscuit's authority
// Block, allowing a consuming party to later select the corresponding public key to validate that
// signature.
func WithRootKeyID(id uint32) biscuitOption {
	return func(b *biscuitOptions) error {
		b.rootKeyID = &id
		return nil
	}
}

func newBiscuit(root crypto.Signer, symbols datalog.SymbolTable, publicKeys datalog.PublicKeyTable, authority *Block, opts ...biscuitOption) (*Biscuit, error) {
	options := biscuitOptions{
		rng: rand.Reader,
	}
	for _, opt := range opts {
		if err := opt(&options); err != nil {
			return nil, err
		}
	}

	if !symbols.IsDisjoint(authority.symbols) {
		return nil, ErrSymbolTableOverlap
	}

	symbols.Extend(authority.symbols)

	signer, err := biscuitcrypto.NewSigner(root)
	if err != nil {
		return nil, fmt.Errorf("biscuit: failed to create signer from root key: %w", err)
	}

	// For now, always infer the next algorithm based on the last one.
	// TODO: Support explicit configuration of biscuit authority block's key algorithm
	nextAlg := signer.Algorithm()

	keyGen, err := biscuitcrypto.NewKeyGenerator(nextAlg)
	if err != nil {
		return nil, err
	}
	nextPublicKey, nextPrivateKey, err := keyGen.GenerateNext(options.rng)
	if err != nil {
		return nil, fmt.Errorf("generating next keypair: %w", err)
	}

	protoAuthority, err := tokenBlockToProtoBlock(authority)
	if err != nil {
		return nil, err
	}
	marshalledAuthority, err := proto.Marshal(protoAuthority)
	if err != nil {
		return nil, err
	}

	// For now, hard-code use of v1 block signatures and don't support use of deprecated v0 block signatures.
	// TODO: Enable optional use of deprecated block signature v0 when generating blocks
	blockSignatureVersion := BlockSignatureVersion1
	signaturePayload := authorityBlockSignaturePayloadV1(nextAlg, marshalledAuthority, nextPublicKey, blockSignatureVersion)
	signature, err := signer.Sign(signaturePayload)
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}

	nextKey := &pb.PublicKey{
		Algorithm: &nextAlg,
		Key:       nextPublicKey,
	}

	signedBlock := &pb.SignedBlock{
		Block:             marshalledAuthority,
		NextKey:           nextKey,
		Signature:         signature,
		ExternalSignature: nil, // Authority blocks should not include external signatures.
		Version:           proto.Uint32(uint32(blockSignatureVersion)),
	}

	proof := &pb.Proof{
		Content: &pb.Proof_NextSecret{
			NextSecret: nextPrivateKey,
		},
	}

	container := &pb.Biscuit{
		RootKeyId: options.rootKeyID,
		Authority: signedBlock,
		Proof:     proof,
	}

	signatureRegistry := &datalog.SignatureRegistry{}
	authority.UpdatePublicKeys(0, &publicKeys, signatureRegistry)

	return &Biscuit{
		authority:         authority,
		symbols:           &symbols,
		publicKeys:        &publicKeys,
		signatureRegistry: signatureRegistry,
		container:         container,
	}, nil
}

func New(rng io.Reader, root ed25519.PrivateKey, baseSymbols datalog.SymbolTable, authority *Block) (*Biscuit, error) {
	var opts []biscuitOption
	if rng != nil {
		opts = []biscuitOption{WithRNG(rng)}
	}
	publicKeys := *datalog.NewPublicKeyTable()
	return newBiscuit(root, baseSymbols, publicKeys, authority, opts...)
}

func (b *Biscuit) CreateBlock(blockID uint64) BlockBuilder {
	bb := NewBlockBuilder()
	bb.SetBlockID(blockID)
	return bb
}

// AppendBlock adds a block to the biscuit using a BlockBuilder
func (b *Biscuit) AppendBlock(rng io.Reader, blockBuilder BlockBuilder) (*Biscuit, error) {
	block := blockBuilder.Build(*b.symbols, *b.publicKeys, *b.signatureRegistry)
	return b.append(rng, block, nil)
}

// append is a private function used by both Append (from which externalSignature should be nil) and
// AppendThirdPartyBlock (from which externalSignature should be non-nil).
func (b *Biscuit) append(rng io.Reader, block *Block, pbExternalSignature *pb.ExternalSignature) (*Biscuit, error) {
	if b.GetContainer() == nil {
		return nil, errors.New("biscuit: append failed biscuit container is nil")
	}

	privateKey := b.GetContainer().GetProof().GetNextSecret()
	if privateKey == nil {
		return nil, errors.New("biscuit: append failed: no private key; token is sealed")
	}

	lastBlock := b.lastBlock()
	lastAlg := lastBlock.GetNextKey().GetAlgorithm()
	signer, err := biscuitcrypto.NewSignerFromPB(lastAlg, privateKey)
	if err != nil {
		return nil, fmt.Errorf("biscuit: unable to create signer from proof: %w", err)
	}

	lastSignature := lastBlock.GetSignature()

	if !b.symbols.IsDisjoint(block.symbols) {
		return nil, ErrSymbolTableOverlap
	}

	// clone biscuit fields and append new block
	authority := new(Block)
	*authority = *b.authority

	blockID := len(b.blocks) + 1
	blocks := make([]*Block, blockID)
	for i, oldBlock := range b.blocks {
		blocks[i] = new(Block)
		*blocks[i] = *oldBlock
	}
	blocks[len(b.blocks)] = block

	var symbols *datalog.SymbolTable
	if !block.IsThirdParty() {
		symbols = b.symbols.Clone()
		symbols.Extend(block.symbols)
	} else {
		// For third-party blocks, preserve the existing symbol table
		// for use by non-third-party blocks
		symbols = b.symbols.Clone()
	}

	// For now, always infer next algorithm from the last one.
	// TODO: Support explicit configuration of appended block's key algorithm
	nextAlg := lastAlg

	keyGen, err := biscuitcrypto.NewKeyGenerator(nextAlg)
	if err != nil {
		return nil, err
	}

	rawNextPub, rawNextPriv, err := keyGen.GenerateNext(rng)
	if err != nil {
		return nil, fmt.Errorf("biscuit: unable to generate next key pair: %w", err)
	}

	// serialize and sign the new block
	protoBlock, err := tokenBlockToProtoBlock(block)
	if err != nil {
		return nil, err
	}
	marshalledBlock, err := proto.Marshal(protoBlock)
	if err != nil {
		return nil, err
	}

	var externalSignatureBytes []byte
	if pbExternalSignature != nil {
		externalSignatureBytes = pbExternalSignature.GetSignature()
	}

	// TODO: Use biscuit-rust's block signature version heuristic when creating biscuits and appending blocks
	// TODO: Enable optional use of deprecated block signature v0 when generating blocks
	signaturePayload := blockSignaturePayloadV1(
		nextAlg,
		marshalledBlock,
		rawNextPub,
		externalSignatureBytes, // May be nil.
		lastSignature,
		BlockSignatureVersion1,
	)

	signature, err := signer.Sign(signaturePayload)
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}
	nextKey := &pb.PublicKey{
		Algorithm: &nextAlg,
		Key:       rawNextPub,
	}

	signedBlock := &pb.SignedBlock{
		Block:             marshalledBlock,
		NextKey:           nextKey,
		Signature:         signature,
		ExternalSignature: pbExternalSignature, // May be nil
		Version:           proto.Uint32(uint32(BlockSignatureVersion1)),
	}

	proof := &pb.Proof{
		Content: &pb.Proof_NextSecret{
			NextSecret: rawNextPriv,
		},
	}

	// clone container and append new marshalled block and public key
	container := &pb.Biscuit{
		Authority: b.container.Authority,
		Blocks:    append([]*pb.SignedBlock{}, b.container.Blocks...),
		Proof:     proof,
	}

	container.Blocks = append(container.Blocks, signedBlock)

	// Update the public key and signature registry
	publicKeys := b.publicKeys.Clone()
	signatureRegistry := b.signatureRegistry.Clone()
	block.UpdatePublicKeys(uint64(blockID), publicKeys, signatureRegistry)

	return &Biscuit{
		authority:         authority,
		blocks:            blocks,
		symbols:           symbols,
		container:         container,
		publicKeys:        publicKeys,
		signatureRegistry: signatureRegistry,
	}, nil
}

// AppendThirdPartyBlock will:
//   - verify the signature from the given ThirdPartyBlockContents, and
//   - return a biscuit instance like the receiver but with the given ThirdPartyBlockContents appended to it.
//
// Cryptographic details of appending such a block are described in [version 3.3 of the Biscuit
// specification](https://github.com/eclipse-biscuit/biscuit/blob/v3.3/SPECIFICATIONS.md).
//
// Currently, v1 block signatures are always used because v0 block signatures are unsupported for third party blocks
// specifically according to the above v3.3 specification.
func (b *Biscuit) AppendThirdPartyBlock(rng io.Reader, contents ThirdPartyBlockContents) (*Biscuit, error) {
	// Verify the external signature using the public key provided in the message.
	err := verifyExternalSignature(
		contents.payload,
		b.lastBlock().GetSignature(),
		contents.externalSignature,
		blockSignatureVersionForThirdPartyBlocks,
	)
	if err != nil {
		return nil, fmt.Errorf("biscuit: failed to verify the external signature of the third party block contents: %w", err)
	}

	nextBlockID := uint64(len(b.blocks))
	block, err := contents.toBlock(nextBlockID)
	if err != nil {
		return nil, fmt.Errorf("biscuit: %w", err)
	}

	return b.append(rng, block, contents.externalSignature)
}

func (b *Biscuit) Seal(_ io.Reader) (*Biscuit, error) {
	if b.container == nil {
		return nil, errors.New("biscuit: token is already sealed")
	}

	privateKey := b.container.Proof.GetNextSecret()
	if privateKey == nil {
		return nil, errors.New("biscuit: token is already sealed")
	}

	lastBlock := b.lastBlock()
	signer, err := biscuitcrypto.NewSignerFromPB(lastBlock.GetNextKey().GetAlgorithm(), privateKey)
	if err != nil {
		return nil, fmt.Errorf("biscuit: unable to create signer: %w", err)
	}

	// clone biscuit fields and append new block
	authority := new(Block)
	*authority = *b.authority

	blocks := make([]*Block, len(b.blocks))
	for i, oldBlock := range b.blocks {
		blocks[i] = new(Block)
		*blocks[i] = *oldBlock
	}

	signature, err := signer.Sign(
		sealedBlockSignaturePayload(
			lastBlock.GetNextKey().GetAlgorithm(),
			lastBlock.GetBlock(),
			lastBlock.GetNextKey().GetKey(),
			lastBlock.GetSignature(),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}

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
		authority:         authority,
		blocks:            blocks,
		symbols:           symbols,
		container:         container,
		publicKeys:        b.publicKeys.Clone(),
		signatureRegistry: b.signatureRegistry.Clone(),
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

// authorizerFor verifies all signatures in the receiver Biscuit and returns an Authorizer wrapping this Biscuit.
func (b *Biscuit) authorizerFor(root crypto.PublicKey) (AuthorizerBuilder, error) {
	verifier, err := biscuitcrypto.NewSigVerifier(root)
	if err != nil {
		return nil, fmt.Errorf("biscuit: failed adapting root public key to a signature verifier: %w", err)
	}

	blockSignatureVersion, err := getBlockSignatureVersion(b.GetContainer().GetAuthority())
	if err != nil {
		return nil, fmt.Errorf("biscuit: failed to parse authority block signature version: %w", err)
	}

	// Generate a signature payload to verify according to the authority block's signature version.
	var toVerify []byte
	switch blockSignatureVersion {
	case BlockSignatureVersion0:
		toVerify = blockSignaturePayloadV0(
			b.GetContainer().GetAuthority().GetNextKey().GetAlgorithm(),
			b.GetContainer().GetAuthority().GetBlock(),
			b.GetContainer().GetAuthority().GetNextKey().GetKey(),
		)
	case BlockSignatureVersion1:
		toVerify = authorityBlockSignaturePayloadV1(
			b.GetContainer().GetAuthority().GetNextKey().GetAlgorithm(),
			b.GetContainer().GetAuthority().GetBlock(),
			b.GetContainer().GetAuthority().GetNextKey().GetKey(),
			blockSignatureVersion,
		)
	default:
		return nil, fmt.Errorf("biscuit: unsupported block signature version in authority block: %d", blockSignatureVersion)
	}

	if err := verifier.Verify(toVerify, b.GetContainer().GetAuthority().GetSignature()); err != nil {
		return nil, err
	}

	// Loop invariants:
	// - verifier is made from the NextKey of the preceding block (or the authority block for the first iteration).
	// - previousSignature is the Signature from the preceding block (or the authority block for the first iteration).
	verifier, err = biscuitcrypto.NewVerifierFromPB(
		b.GetContainer().GetAuthority().GetNextKey().GetAlgorithm(),
		b.GetContainer().GetAuthority().GetNextKey().GetKey(),
	)
	if err != nil {
		return nil, fmt.Errorf("biscuit: authority block's next key parsing failed: %w", err)
	}
	previousSignature := b.GetContainer().GetAuthority().GetSignature()

	for idx, block := range b.GetContainer().GetBlocks() {
		blockSignatureVersion, err := getBlockSignatureVersion(block)
		if err != nil {
			return nil, fmt.Errorf("biscuit: failed to parse block %d signature version: %w", idx, err)
		}

		externalSignature := block.GetExternalSignature().GetSignature() // This may be nil.

		var toVerify []byte
		switch blockSignatureVersion {
		case BlockSignatureVersion0:
			toVerify = blockSignaturePayloadV0(
				block.NextKey.GetAlgorithm(),
				block.GetBlock(),
				block.NextKey.GetKey(),
			)
		case BlockSignatureVersion1:
			toVerify = blockSignaturePayloadV1(
				block.GetNextKey().GetAlgorithm(),
				block.GetBlock(),
				block.GetNextKey().GetKey(),
				externalSignature,
				previousSignature,
				blockSignatureVersion,
			)
		default:
			return nil, fmt.Errorf("biscuit: block %d uses an unsupported block signature version: %d", idx, blockSignatureVersion)
		}

		if err := verifier.Verify(toVerify, block.GetSignature()); err != nil {
			return nil, fmt.Errorf("biscuit: block %d signature verification failed: %w", idx, err)
		}

		if externalSignature != nil {
			err = verifyExternalSignature(
				block.GetBlock(),
				previousSignature,
				block.GetExternalSignature(),
				blockSignatureVersion,
			)
			if err != nil {
				return nil, fmt.Errorf("biscuit: block %d external signature verification failed: %w", idx, err)
			}
		}

		verifier, err = biscuitcrypto.NewVerifierFromPB(block.NextKey.GetAlgorithm(), block.NextKey.GetKey())
		if err != nil {
			return nil, fmt.Errorf("biscuit: block %d next key field could not be parsed: %w", idx, err)
		}
		previousSignature = block.GetSignature()
	}

	switch {
	case b.GetContainer().GetProof().GetNextSecret() != nil:
		privateKey := b.GetContainer().GetProof().GetNextSecret()
		if privateKey == nil {
			return nil, errors.New("biscuit: no next secret in proof")
		}

		signer, err := biscuitcrypto.NewSignerFromPB(b.lastBlock().GetNextKey().GetAlgorithm(), privateKey)
		if err != nil {
			return nil, err
		}

		if err := verifier.Matches(signer); err != nil {
			return nil, fmt.Errorf("biscuit: invalid last signature: %w", err)
		}
	case b.GetContainer().GetProof().GetFinalSignature() != nil:
		signature := b.GetContainer().GetProof().GetFinalSignature()
		lastBlock := b.lastBlock()
		toVerify := sealedBlockSignaturePayload(
			lastBlock.NextKey.GetAlgorithm(),
			lastBlock.Block,
			lastBlock.NextKey.Key,
			lastBlock.Signature,
		)

		if err := verifier.Verify(toVerify, signature); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("biscuit: cannot find proof")
	}

	return NewAuthorizerBuilder(b), nil
}

// AuthorizerFor selects from the supplied source a root public key to use to verify the signatures
// on the biscuit's blocks, returning an error satisfying errors.Is(err, ErrNoPublicKeyAvailable) if
// no such public key is available. If the signatures are valid, it creates an [Authorizer], which
// can then test the authorization policies and accept or refuse the request.
func (b *Biscuit) AuthorizerFor(keySource PublickKeyByIDProjection) (AuthorizerBuilder, error) {
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
	return b.authorizerFor(rootPublicKey)
}

func (b *Biscuit) AuthorizerForCryptoPubKey(pub crypto.PublicKey) (AuthorizerBuilder, error) {
	return b.authorizerFor(pub)
}

// TODO: Add "Deprecated" note to the "(*Biscuit).Authorizer" method, recommending use of
// "(*Biscuit).AuthorizerFor" instead. Wait until after we release the module with the latter
// available, per https://go.dev/wiki/Deprecated.

// Authorizer checks the signature and creates an [AuthorizerBuilder]. The Authorizer can then test the
// authorization policies and accept or refuse the request.
func (b *Biscuit) Authorizer(root ed25519.PublicKey) (AuthorizerBuilder, error) {
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

func (b *Biscuit) GetContainer() *pb.Biscuit {
	if b == nil {
		return nil
	}

	return b.container
}

func (b *Biscuit) GetSymbols() *datalog.SymbolTable {
	if b == nil {
		return nil
	}

	return b.symbols
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
	datalogFact := fact.convert(symbols)

	for _, f := range b.authority.facts {
		if f.Equal(datalogFact) {
			return 0, nil
		}
	}

	for i, block := range b.blocks {
		for _, fact := range block.facts {
			if fact.Equal(datalogFact) {
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

	{
		origin := *datalog.NewOrigin(0)
		for _, fact := range b.authority.facts {
			world.AddFact(origin, fact)
		}
	}

	{
		trustedOrigin := *datalog.NewTrustedOrigin()
		for _, rule := range b.authority.rules {
			world.AddRule(trustedOrigin, 0, rule)
		}
	}

	for i, block := range b.blocks {
		blockID := uint64(i + 1)

		for _, fact := range block.facts {
			world.AddFact(*datalog.NewOrigin(blockID), fact)
		}

		for _, rule := range block.rules {
			trustedOrigin := *datalog.NewTrustedOrigin().With(blockID)
			world.AddRule(trustedOrigin, datalog.BlockID(blockID), rule)
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

func (b *Biscuit) lastBlock() *pb.SignedBlock {
	if len(b.blocks) == 0 {
		return b.container.Authority
	}
	return b.container.Blocks[len(b.blocks)-1]
}

func (b *Biscuit) Blocks() iter.Seq[*Block] {
	return func(yield func(*Block) bool) {
		if b.authority != nil {
			if !yield(b.authority) {
				return
			}
		}
		for _, block := range b.blocks {
			if !yield(block) {
				return
			}
		}
	}
}

// blockSignaturePayloadV0 generates the payload needed to either generate or verify a signed Block using a v0 Block
// signature. Version 0 Block signatures are deprecated.
//
// See the v3.3 specification for details: https://github.com/eclipse-biscuit/biscuit/blob/v3.3/SPECIFICATIONS.md#version-0-deprecated)
func blockSignaturePayloadV0(nextAlg pb.PublicKey_Algorithm, rawBlock, nextPubKey []byte) []byte {
	toSignAlgorithm := make([]byte, 4)
	binary.LittleEndian.PutUint32(toSignAlgorithm[0:], uint32(nextAlg))
	toSign := append(rawBlock[:], toSignAlgorithm...)
	toSign = append(toSign, nextPubKey[:]...)
	return toSign
}

// sealedBlockSignaturePayload generates the payload needed for generating and verifying a biscuit proof containing a
// final signature.
//
// See the v3.3 specification for details regarding both signing and verifying:
//
//   - https://github.com/eclipse-biscuit/biscuit/blob/v3.3/SPECIFICATIONS.md#signature-sealing
//   - https://github.com/eclipse-biscuit/biscuit/blob/v3.3/SPECIFICATIONS.md#verifying-sealed
func sealedBlockSignaturePayload(nextAlg pb.PublicKey_Algorithm, rawBlock, nextPubKey, signature []byte) []byte {
	toSignAlgorithm := make([]byte, 4)
	binary.LittleEndian.PutUint32(toSignAlgorithm[0:], uint32(nextAlg))
	toSign := append(rawBlock[:], toSignAlgorithm...)
	toSign = append(toSign, nextPubKey[:]...)
	toSign = append(toSign, signature[:]...)
	return toSign
}

// authorityBlockSignaturePayloadV1 generates the payload needed to either generate or verify an authority block
// using v1 block signatures.
//
// See the v3.3 specification for details: https://github.com/eclipse-biscuit/biscuit/blob/v3.3/SPECIFICATIONS.md#version-1
func authorityBlockSignaturePayloadV1(nextAlg pb.PublicKey_Algorithm, rawBlock, nextPubKey []byte, version BlockSignatureVersion) []byte {
	versionLE := make([]byte, 4)
	binary.LittleEndian.PutUint32(versionLE[0:], uint32(version))
	toSign := append([]byte("\000BLOCK\000\000VERSION\000"), versionLE...)

	toSign = append(toSign, []byte("\000PAYLOAD\000")...)
	toSign = append(toSign, rawBlock...)

	toSign = append(toSign, []byte("\000ALGORITHM\000")...)
	toSignAlgorithm := make([]byte, 4)
	binary.LittleEndian.PutUint32(toSignAlgorithm[0:], uint32(nextAlg))
	toSign = append(toSign, toSignAlgorithm...)

	toSign = append(toSign, []byte("\000NEXTKEY\000")...)
	toSign = append(toSign, nextPubKey...)

	return toSign
}

// blockSignaturePayloadV1 generates the payload needed to either generate or verify an appended block (i.e., one
// appearing after the authority block) using v1 block signatures. Currently, only BlockSignatureVersionV1 is supported.
//
// Note that externalSignature is an optional parameter. Pass nil here to represent that there is no external signature.
//
// See the v3.3 specification for details: https://github.com/eclipse-biscuit/biscuit/blob/v3.3/SPECIFICATIONS.md#version-1
func blockSignaturePayloadV1(nextAlg pb.PublicKey_Algorithm, rawBlock, nextPubKey, externalSignature, previousSignature []byte, version BlockSignatureVersion) []byte {
	versionLE := make([]byte, 4)
	binary.LittleEndian.PutUint32(versionLE[0:], uint32(version))
	toSign := append([]byte("\000BLOCK\000\000VERSION\000"), versionLE...)

	toSign = append(toSign, []byte("\000PAYLOAD\000")...)
	toSign = append(toSign, rawBlock...)

	toSign = append(toSign, []byte("\000ALGORITHM\000")...)
	toSignAlgorithm := make([]byte, 4)
	binary.LittleEndian.PutUint32(toSignAlgorithm[0:], uint32(nextAlg))
	toSign = append(toSign, toSignAlgorithm...)

	toSign = append(toSign, []byte("\000NEXTKEY\000")...)
	toSign = append(toSign, nextPubKey...)

	toSign = append(toSign, []byte("\000PREVSIG\000")...)
	toSign = append(toSign, previousSignature...)

	if externalSignature != nil {
		toSign = append(toSign, []byte("\000EXTERNALSIG\000")...)
		toSign = append(toSign, externalSignature...)
	}

	return toSign
}

// blockSignaturePayloadV1 generates the payload needed to either generate or verify an external signature of a block
// using v1 block signatures.
//
// See the v3.3 specification for details: https://github.com/eclipse-biscuit/biscuit/blob/v3.3/SPECIFICATIONS.md#version-1
func externalSignaturePayloadV1(payload, previousSignature []byte, version BlockSignatureVersion) []byte {
	versionLE := make([]byte, 4)
	binary.LittleEndian.PutUint32(versionLE[0:], uint32(version))
	toSign := append([]byte("\000EXTERNAL\000\000VERSION\000"), versionLE...)

	toSign = append(toSign, []byte("\000PAYLOAD\000")...)
	toSign = append(toSign, payload...)

	toSign = append(toSign, []byte("\000PREVSIG\000")...)
	toSign = append(toSign, previousSignature...)

	return toSign
}

// verifyExternalSignature verifies an external signature of a block using the external signature message's public key.
//
// Currently, only BlockSignatureVersion1 is supported.
func verifyExternalSignature(payload []byte, previousSignature []byte, externalSignature *pb.ExternalSignature, version BlockSignatureVersion) error {
	if externalSignature == nil {
		return errors.New("external signature is nil")
	}

	if version != BlockSignatureVersion1 {
		return fmt.Errorf("unsupported block signature version, %d; only v1 is supported", version)
	}

	toVerify := externalSignaturePayloadV1(payload, previousSignature, version)

	verifier, err := biscuitcrypto.NewVerifierFromPB(
		externalSignature.GetPublicKey().GetAlgorithm(),
		externalSignature.GetPublicKey().GetKey(),
	)
	if err != nil {
		return fmt.Errorf("failed parsing external signature's public key: %w", err)
	}

	return verifier.Verify(toVerify, externalSignature.GetSignature())
}

func (b *Biscuit) ThirdPartyBlockRequest() (ThirdPartyBlockRequest, error) {
	var none ThirdPartyBlockRequest

	if b == nil {
		return none, errors.New("third_party: biscuit is nil")
	}
	if b.container == nil {
		return none, errors.New("third_party: biscuit's inner container is nil")
	}

	proof := b.container.GetProof()
	if proof == nil {
		return none, errors.New("third_party: proof is missing")
	}
	privateKey := proof.GetNextSecret()
	if privateKey == nil {
		return none, errors.New("third_party: request failed, token is sealed")
	}

	// Get the most recent block signature: if there are no appended blocks, use the authority block's signature; if
	// there are any appended blocks, use the last of these in the list.
	var previousSignature []byte
	numBlocks := len(b.container.GetBlocks())
	if numBlocks == 0 {
		previousSignature = b.container.GetAuthority().GetSignature()
	} else {
		previousSignature = b.container.GetBlocks()[numBlocks-1].GetSignature()
	}

	return ThirdPartyBlockRequest{
		previousSignature: previousSignature,
	}, nil
}
