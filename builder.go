package biscuit

import (
	"crypto"
	"crypto/ed25519"
	"errors"

	"google.golang.org/protobuf/proto"

	"github.com/eclipse-biscuit/biscuit-go/v2/datalog"
	"github.com/eclipse-biscuit/biscuit-go/v2/pb"
)

var (
	ErrDuplicateFact     = errors.New("biscuit: fact already exists")
	ErrInvalidBlockIndex = errors.New("biscuit: invalid block index")
)

type Builder interface {
	AddBlock(block ParsedBlock) error
	AddAuthorityFact(fact Fact) error
	AddAuthorityRule(rule Rule) error
	AddAuthorityCheck(check Check) error
	SetContext(string)
	BuildWithSymbols(datalog.SymbolTable, datalog.PublicKeyTable) (*Biscuit, error)
	Build() (*Biscuit, error)
}

type biscuitBuilder struct {
	rootKey        crypto.Signer
	authorityBlock BlockBuilder
	biscuitOptions []biscuitOption
}

func NewBuilder(root ed25519.PrivateKey, opts ...biscuitOption) Builder {
	b := &biscuitBuilder{
		rootKey:        root,
		authorityBlock: NewBlockBuilder(),
		biscuitOptions: opts,
	}

	return b
}

func NewBuilderSigner(root crypto.Signer, opts ...biscuitOption) Builder {
	b := &biscuitBuilder{
		rootKey:        root,
		authorityBlock: NewBlockBuilder(),
		biscuitOptions: opts,
	}

	return b
}

func (b *biscuitBuilder) AddBlock(block ParsedBlock) error {
	for f := range block.Facts.Iter() {
		if err := b.AddAuthorityFact(f); err != nil {
			return err
		}
	}
	for _, r := range block.Rules {
		err := b.AddAuthorityRule(r)
		if err != nil {
			return err
		}
	}
	for _, c := range block.Checks {
		err := b.AddAuthorityCheck(c)
		if err != nil {
			return err
		}
	}

	return nil
}

func (b *biscuitBuilder) AddAuthorityFact(fact Fact) error {
	return b.authorityBlock.AddFact(fact)
}

func (b *biscuitBuilder) AddAuthorityRule(rule Rule) error {
	return b.authorityBlock.AddRule(rule)
}

func (b *biscuitBuilder) AddAuthorityCheck(check Check) error {
	return b.authorityBlock.AddCheck(check)
}

func (b *biscuitBuilder) SetContext(context string) {
	b.authorityBlock.SetContext(context)
}

func (b *biscuitBuilder) Build() (*Biscuit, error) {
	return b.BuildWithSymbols(*defaultSymbolTable.Clone(), *datalog.NewPublicKeyTable())
}

func (b *biscuitBuilder) BuildWithSymbols(
	symbols datalog.SymbolTable,
	publicKeys datalog.PublicKeyTable,
) (*Biscuit, error) {
	authorityBlock := b.authorityBlock.Build(symbols, publicKeys, datalog.SignatureRegistry{})

	// TODO: Use biscuit-rust's datalog version heuristic when creating biscuits and appending signedBlocks
	authorityBlock.version = DatalogVersion3_3

	return newBiscuit(
		b.rootKey,
		symbols,
		publicKeys,
		authorityBlock,
		b.biscuitOptions...,
	)
}

type Unmarshaler struct {
	Symbols *datalog.SymbolTable
}

func Unmarshal(serialized []byte) (*Biscuit, error) {
	return (&Unmarshaler{Symbols: defaultSymbolTable.Clone()}).Unmarshal(serialized)
}

func (u *Unmarshaler) Unmarshal(serialized []byte) (*Biscuit, error) {
	if u.Symbols == nil {
		return nil, errors.New("biscuit: unmarshaler requires a symbol table")
	}

	symbols := u.Symbols.Clone()
	publicKeys := datalog.NewPublicKeyTable()
	signatureRegistry := &datalog.SignatureRegistry{}

	container := new(pb.Biscuit)
	if err := proto.Unmarshal(serialized, container); err != nil {
		return nil, err
	}

	if err := verifySignedBlockCryptoSizes(container.Authority); err != nil {
		return nil, err
	}

	pbAuthority := new(pb.Block)
	if err := proto.Unmarshal(container.Authority.Block, pbAuthority); err != nil {
		return nil, err
	}

	authority, err := protoBlockToTokenBlock(pbAuthority, nil)
	if err != nil {
		return nil, err
	}

	symbols.Extend(authority.symbols)
	authority.UpdatePublicKeys(0, publicKeys, signatureRegistry)

	blocks := make([]*Block, len(container.Blocks))
	for i, sb := range container.Blocks {
		if err := verifySignedBlockCryptoSizes(sb); err != nil {
			return nil, err
		}

		blockID := uint64(i) + 1

		pbBlock := new(pb.Block)
		if err := proto.Unmarshal(sb.Block, pbBlock); err != nil {
			return nil, err
		}

		tokenBlock, err := protoBlockToTokenBlock(pbBlock, sb.GetExternalSignature())
		if err != nil {
			return nil, err
		}

		blocks[i] = tokenBlock

		if !tokenBlock.IsThirdParty() {
			symbols.Extend(tokenBlock.symbols)
		} else {
			tokenBlock.symbols.Extend(tokenBlock.symbols)
		}

		symbols.Extend(tokenBlock.symbols)
		tokenBlock.UpdatePublicKeys(blockID, publicKeys, signatureRegistry)
	}

	result := &Biscuit{
		authority:         authority,
		symbols:           symbols,
		publicKeys:        publicKeys,
		signatureRegistry: signatureRegistry,
		blocks:            blocks,
		container:         container,
	}

	return result, nil
}

type BlockBuilder interface {
	AddBlock(block ParsedBlock) error
	AddFact(fact Fact) error
	AddRule(rule Rule) error
	AddCheck(check Check) error
	AddScope(scope Scope) error
	SetContext(string)
	SetBlockID(uint64)
	Build(datalog.SymbolTable, datalog.PublicKeyTable, datalog.SignatureRegistry) *Block
}

type blockBuilder struct {
	symbolsStart int
	facts        *FactSet
	rules        []Rule
	checks       []Check
	scopes       []Scope
	context      string
	blockID      uint64
	buildOptions []BlockBuilderOption
}

var _ BlockBuilder = (*blockBuilder)(nil)

// blockBuilderConfig is used by the [BlockBuilder] when building blocks to enable [BlockBuilderOption].
type blockBuilderConfig struct {
	symbols           datalog.SymbolTable
	symbolsStart      int
	publicKeys        datalog.PublicKeyTable
	publicKeysStart   int
	signatureRegistry datalog.SignatureRegistry
}

// BlockBuilderOption allows custom block builder dependency injection, which should only really be needed for testing.
type BlockBuilderOption func(*blockBuilderConfig)

func WithSymbolStart(start int) BlockBuilderOption {
	return func(b *blockBuilderConfig) {
		b.symbolsStart = start
	}
}

func NewBlockBuilder(opts ...BlockBuilderOption) BlockBuilder {
	return &blockBuilder{
		blockID:      0,
		buildOptions: opts,
		facts:        NewFactSet(),
	}
}

func (b *blockBuilder) AddBlock(block ParsedBlock) error {
	for f := range block.Facts.Iter() {
		err := b.AddFact(f)
		if err != nil {
			return err
		}
	}
	for _, r := range block.Rules {
		err := b.AddRule(r)
		if err != nil {
			return err
		}
	}
	for _, c := range block.Checks {
		err := b.AddCheck(c)
		if err != nil {
			return err
		}
	}
	for _, s := range block.Scope {
		err := b.AddScope(s)
		if err != nil {
			return err
		}
	}

	return nil
}

func (b *blockBuilder) AddFact(fact Fact) error {
	if wasInserted := b.facts.Insert(fact); !wasInserted {
		return ErrDuplicateFact
	}

	return nil
}

func (b *blockBuilder) AddRule(rule Rule) error {
	b.rules = append(b.rules, rule)

	return nil
}

func (b *blockBuilder) AddScope(scope Scope) error {
	b.scopes = append(b.scopes, scope)

	return nil
}

func (b *blockBuilder) AddCheck(check Check) error {
	b.checks = append(b.checks, check)

	return nil
}

func (b *blockBuilder) SetContext(context string) {
	b.context = context
}

func (b *blockBuilder) SetBlockID(blockID uint64) {
	b.blockID = blockID
}

func (b *blockBuilder) Build(
	symbols datalog.SymbolTable,
	publicKeys datalog.PublicKeyTable,
	signatureRegistry datalog.SignatureRegistry,
) *Block {
	config := blockBuilderConfig{
		symbols:           symbols,
		symbolsStart:      len(symbols),
		publicKeys:        publicKeys,
		publicKeysStart:   len(publicKeys),
		signatureRegistry: signatureRegistry,
	}

	for _, opt := range b.buildOptions {
		opt(&config)
	}

	facts := make([]datalog.Fact, b.facts.Size())
	{
		index := 0
		for fact := range b.facts.Iter() {
			dlFact := fact.convert(&config.symbols)
			facts[index] = dlFact
			index++
		}
	}

	rules := make([]datalog.Rule, 0, len(b.rules))
	for _, rule := range b.rules {
		dlRule := rule.Convert(&config.symbols, &config.publicKeys)
		rules = append(rules, dlRule)
	}

	dlChecks := make([]datalog.Check, 0, len(b.checks))
	for _, check := range b.checks {
		dlCheck := check.Convert(&config.symbols, &config.publicKeys)

		dlChecks = append(dlChecks, dlCheck)
	}

	scopes := make([]datalog.Scope, 0, len(b.scopes))
	for _, scope := range b.scopes {
		dlScope := scope.convert(&config.publicKeys)
		scopes = append(scopes, dlScope)
	}

	return &Block{
		symbols:    config.symbols.SplitOff(config.symbolsStart),
		publicKeys: config.publicKeys.SplitOff(config.publicKeysStart),
		facts:      facts,
		rules:      rules,
		scopes:     scopes,
		checks:     dlChecks,
		context:    b.context,

		// TODO: Use biscuit-rust's datalog version heuristic when creating biscuits and appending signedBlocks
		// - This is a hack to add some initial support for third party signedBlocks to biscuit-go.
		version: minimumDatalogVersionForThirdPartyBlocks,
	}
}

// TODO determine whether this is required to check before further unmarshalling, or if we could just rely on
// internal/crypto package to check key/signature sizes as they are being decoded. Ideally, size checks around keys and
// signatures should be done closer to the decoding code.
func verifySignedBlockCryptoSizes(sb *pb.SignedBlock) error {
	switch sb.GetNextKey().GetAlgorithm() {
	case pb.PublicKey_Ed25519:
		if len(sb.NextKey.Key) != ed25519.PublicKeySize {
			return ErrInvalidKeySize
		}
		if len(sb.Signature) != ed25519.SignatureSize {
			return ErrInvalidSignatureSize
		}

	case pb.PublicKey_SECP256R1:
		// Pub key size for SEC1 compressed representation is ⌊1 + ((256 + 7)/8)⌋ where 256 is bitsize for curve
		//
		// ref: https://cs.opensource.google/go/go/+/refs/tags/go1.24.0:src/crypto/elliptic/elliptic.go;l=185
		if len(sb.NextKey.Key) != 33 {
			return ErrInvalidKeySize
		}
		// Size for an ASN.1 encoded secp256r1 signature is bounded at 73 bytes.
		//
		// ref:
		//   - https://www.itu.int/rec/t-rec-x.690/en
		//   - https://crypto.stackexchange.com/a/83977
		if len(sb.Signature) > 73 {
			return ErrInvalidSignatureSize
		}

	default:
		return errors.New("biscuit: unknown signature algorithm in authority block")
	}

	return nil
}
