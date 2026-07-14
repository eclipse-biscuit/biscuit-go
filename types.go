package biscuit

import (
	"bytes"
	"cmp"
	"encoding/hex"
	"fmt"
	"iter"
	"sort"
	"strings"
	"time"

	"github.com/eclipse-biscuit/biscuit-go/v2/datalog"
	"github.com/eclipse-biscuit/biscuit-go/v2/internal/set"
	"github.com/eclipse-biscuit/biscuit-go/v2/pb"
)

type BlockSignatureVersion uint32

const (
	BlockSignatureVersion0 BlockSignatureVersion = 0
	BlockSignatureVersion1 BlockSignatureVersion = 1

	MinBlockSignatureVersion = BlockSignatureVersion0
	MaxBlockSignatureVersion = BlockSignatureVersion1
)

func getBlockSignatureVersion(block *pb.SignedBlock) (BlockSignatureVersion, error) {
	version := BlockSignatureVersion(block.GetVersion())
	if version < MinBlockSignatureVersion {
		return 0, fmt.Errorf("unsupported block signature version: version %d is less than minimum version %d", version, MinBlockSignatureVersion)
	}
	if version > MaxBlockSignatureVersion {
		return 0, fmt.Errorf("unsupported block signature version: version %d is greater than maximum version %d", version, MaxBlockSignatureVersion)
	}
	return version, nil
}

type DatalogVersion uint32

const (
	DatalogVersion3_0 = DatalogVersion(3)
	// DatalogVersion3_1 introduces "check all", bitwise operators, != and more.
	DatalogVersion3_1 = DatalogVersion(4)
	// DatalogVersion3_2 introduces third party blocks
	DatalogVersion3_2 = DatalogVersion(5)
	// DatalogVersion3_3 introduces "reject if", closures, array/map, null, external functions, and more.
	DatalogVersion3_3 = DatalogVersion(6)

	MinSchemaVersion = DatalogVersion3_0
	MaxSchemaVersion = DatalogVersion3_3
)

func getDatalogVersion(block *pb.Block) (DatalogVersion, error) {
	version := DatalogVersion(block.GetVersion())
	if version < MinSchemaVersion {
		return 0, fmt.Errorf("unsupported block datalog version: version %d is less than minimum version %d", version, MinSchemaVersion)
	}
	if version > MaxSchemaVersion {
		return 0, fmt.Errorf("unsupported block datalog version: version %d is greater than maximum version %d", version, MaxSchemaVersion)
	}
	return version, nil
}

// defaultSymbolTable predefines some symbols available in every implementation, to avoid
// transmitting them with every token
var defaultSymbolTable = &datalog.SymbolTable{}

type ExternalSignature struct {
	publicKey datalog.PublicKey
	signature []byte
}

type Block struct {
	symbols           *datalog.SymbolTable
	publicKeys        *datalog.PublicKeyTable
	facts             []datalog.Fact
	scopes            []datalog.Scope
	rules             []datalog.Rule
	checks            []datalog.Check
	context           string
	version           DatalogVersion
	externalSignature *ExternalSignature
}

func (b *Block) Code(symbols *datalog.SymbolTable) string {
	debug := &datalog.SymbolDebugger{
		SymbolTable: symbols,
	}

	facts := make([]string, len(b.facts))
	for i, f := range b.facts {
		facts[i] = debug.Predicate(f.Predicate)
	}

	rules := make([]string, len(b.rules))
	for i, r := range b.rules {
		rules[i] = debug.Rule(r)
	}

	checks := make([]string, len(b.checks))
	for i, c := range b.checks {
		checks[i] = debug.Check(c)
	}

	scopes := make([]string, len(b.scopes))
	for i, s := range b.scopes {
		scopes[i] = debug.Scope(s)
	}

	return fmt.Sprintf(`Block {
		%v
		%s
		%s
		%s
	}`,
		strings.Join(facts, ";\n"),
		strings.Join(rules, ";\n"),
		strings.Join(checks, ";\n"),
		strings.Join(scopes, ";\n"),
	)
}

func (b *Block) String(symbols *datalog.SymbolTable) string {
	debug := &datalog.SymbolDebugger{
		SymbolTable: symbols,
	}

	facts := make([]string, len(b.facts))
	for i, f := range b.facts {
		facts[i] = debug.Predicate(f.Predicate)
	}

	rules := make([]string, len(b.rules))
	for i, r := range b.rules {
		rules[i] = debug.Rule(r)
	}

	checks := make([]string, len(b.checks))
	for i, c := range b.checks {
		checks[i] = debug.Check(c)
	}

	scopes := make([]string, len(b.scopes))
	for i, s := range b.scopes {
		scopes[i] = debug.Scope(s)
	}

	return fmt.Sprintf(`Block {
		symbols: %+q
		context: %q
		facts: %v
		rules: %v
		checks: %v
		scopes: %v
		authorizerChecks: [%s]
		version: %d
	}`,
		*b.symbols,
		b.context,
		debug.Facts(b.facts),
		rules,
		checks,
		scopes,
		strings.Join(checks, ", "),
		b.version,
	)
}

// UpdatePublicKeys may add public keys to the public key table and the signature registry.
func (b *Block) UpdatePublicKeys(blockID uint64, publicKeys *datalog.PublicKeyTable, signatureRegistry *datalog.SignatureRegistry) {
	if b.IsThirdParty() {
		// Is a third party block
		publicKey := b.externalSignature.publicKey
		index := publicKeys.Insert(publicKey)
		signatureRegistry.Insert(index, datalog.BlockID(blockID))
	} else {
		// Is not a third party block.
		if b.publicKeys != nil {
			publicKeys.Extend(b.publicKeys)
		}
	}
}

func (b *Block) IsThirdParty() bool {
	return b.externalSignature != nil
}

type FactSet struct {
	set.HashSet[Fact]
}

func NewFactSet(facts ...Fact) *FactSet {
	return &FactSet{*set.NewHashSet[Fact](facts...)}
}

func (fs FactSet) String() string {
	out := make([]string, fs.Size())
	{
		i := 0
		for f := range fs.Iter() {
			out[i] = f.String()
			i++
		}
	}

	var outStr string
	if len(out) > 0 {
		outStr = fmt.Sprintf("\n\t%s\n", strings.Join(out, ",\n\t"))
	}

	return fmt.Sprintf("[%s]", outStr)
}

type ParsedBlock struct {
	Facts  FactSet
	Rules  []Rule
	Checks []Check
	Scope  []Scope
}

type ParsedAuthorizer struct {
	Policies []Policy
	Block    ParsedBlock
}
type Fact struct {
	Predicate
}

func (f Fact) convert(symbols *datalog.SymbolTable) datalog.Fact {
	return datalog.Fact{
		Predicate: f.Predicate.convert(symbols),
	}
}

func (f Fact) String() string {
	return f.Predicate.String()
}

func (f Fact) Compare(f2 Fact) int {
	return f.Predicate.Compare(f2.Predicate)
}

func (f Fact) Equal(f2 Fact) bool {
	return f.Compare(f2) == 0
}

var _ set.Ordered[Fact] = (*Fact)(nil)
var _ set.Hashable[Fact] = (*Fact)(nil)

func fromDatalogFact(symbols *datalog.SymbolTable, f datalog.Fact) (*Fact, error) {
	pred, err := fromDatalogPredicate(symbols, f.Predicate)
	if err != nil {
		return nil, err
	}

	return &Fact{
		Predicate: *pred,
	}, nil
}

func fromDatalogPredicate(symbols *datalog.SymbolTable, p datalog.Predicate) (*Predicate, error) {
	terms := make([]Term, len(p.Terms))
	for i, id := range p.Terms {
		a, err := fromDatalogID(symbols, id)
		if err != nil {
			return nil, err
		}
		terms[i] = a
	}

	return &Predicate{
		Name: symbols.Str(p.Name),
		IDs:  terms,
	}, nil
}

func fromDatalogID(symbols *datalog.SymbolTable, id datalog.Term) (Term, error) {
	var a Term
	switch id.Type() {
	case datalog.TermTypeVariable:
		a = Variable(symbols.Str(datalog.String(id.(datalog.Variable))))
	case datalog.TermTypeInteger:
		a = Integer(id.(datalog.Integer))
	case datalog.TermTypeString:
		a = String(symbols.Str(id.(datalog.String)))
	case datalog.TermTypeDate:
		a = Date(time.Unix(int64(id.(datalog.Date)), 0))
	case datalog.TermTypeBytes:
		a = Bytes(id.(datalog.Bytes))
	case datalog.TermTypeBool:
		a = Bool(id.(datalog.Bool))
	case datalog.TermTypeSet:
		setIDs := id.(datalog.Set)
		terms := make([]Term, setIDs.Size())

		{
			i := 0
			for term := range setIDs.Iter() {
				setTerm, err := fromDatalogID(symbols, term)
				if err != nil {
					return nil, err
				}

				terms[i] = setTerm
				i++
			}
		}

		a = NewSet(terms...)
	default:
		return nil, fmt.Errorf("unsupported term type: %v", id.Type())
	}

	return a, nil
}

type PublicKey struct {
	Algorithm pb.PublicKey_Algorithm
	Bytes     []byte
}

func NewPublicKey(algorithm, hexBytes string) (*PublicKey, error) {
	pk := PublicKey{}

	// Convert algorithm string to protobuf type.
	switch strings.ToLower(algorithm) {
	case "secp256r1":
		pk.Algorithm = pb.PublicKey_SECP256R1
	case "ed25519":
		pk.Algorithm = pb.PublicKey_Ed25519
	default:
		return nil, fmt.Errorf("unsupported algorithm: %v", algorithm)
	}

	// Decode the hexBytes string.
	b, err := hex.DecodeString(hexBytes)
	if err != nil {
		return nil, err
	}
	pk.Bytes = b

	return &pk, nil
}

func (pk *PublicKey) convert() datalog.PublicKey {
	return datalog.PublicKey{
		Algorithm: pk.Algorithm,
		Key:       pk.Bytes,
	}
}

func (pk *PublicKey) Compare(pk2 *PublicKey) int {
	if x := cmp.Compare(pk.Algorithm, pk2.Algorithm); x != 0 {
		return x
	}
	return bytes.Compare(pk.Bytes, pk2.Bytes)
}

var _ set.Ordered[*PublicKey] = (*PublicKey)(nil)

type ScopeType uint

const (
	AuthorityScopeType ScopeType = iota
	PreviousScopeType
	PublicKeyScopeType
)

func (st ScopeType) convert() datalog.ScopeType {
	return datalog.ScopeType(st)
}

type Scope struct {
	Type      ScopeType
	PublicKey *PublicKey
}

func (s Scope) convert(publicKeyTable *datalog.PublicKeyTable) datalog.Scope {
	var index uint64
	if s.PublicKey != nil {
		index = publicKeyTable.Insert(s.PublicKey.convert())
	}

	return datalog.Scope{
		Type:                s.Type.convert(),
		PublicKeyTableIndex: index,
	}
}

func (s Scope) Compare(s2 Scope) int {
	if x := cmp.Compare(s.Type, s2.Type); x != 0 {
		return x
	}
	return s.PublicKey.Compare(s2.PublicKey)
}

var _ set.Ordered[Scope] = (*Scope)(nil)

func fromDatalogScope(publicKeys *datalog.PublicKeyTable, dlScope datalog.Scope) (*Scope, error) {
	var scopeType ScopeType
	var publicKey *PublicKey
	switch dlScope.Type {
	case datalog.AuthorityScopeType:
		scopeType = AuthorityScopeType
	case datalog.PreviousScopeType:
		scopeType = PreviousScopeType
	case datalog.PublicKeyScopeType:
		scopeType = PublicKeyScopeType

		if dlScope.PublicKeyTableIndex >= uint64(len(*publicKeys)) {
			return nil, fmt.Errorf("invalid public key table index: %d", dlScope.PublicKeyTableIndex)
		}
		dlPublicKey := (*publicKeys)[dlScope.PublicKeyTableIndex]
		publicKey = &PublicKey{
			Algorithm: dlPublicKey.Algorithm,
			Bytes:     dlPublicKey.Key,
		}
	default:
		return nil, fmt.Errorf("unsupported scope: %v", dlScope.Type)
	}

	return &Scope{
		Type:      scopeType,
		PublicKey: publicKey,
	}, nil
}

type Rule struct {
	Head        Predicate
	Body        []Predicate
	Expressions []Expression
	Scopes      []Scope
}

func (r Rule) Convert(
	symbols *datalog.SymbolTable,
	publicKeys *datalog.PublicKeyTable,
) datalog.Rule {
	dlBody := make([]datalog.Predicate, len(r.Body))
	for i, p := range r.Body {
		dlBody[i] = p.convert(symbols)
	}

	dlExpressions := make([]datalog.Expression, len(r.Expressions))
	for i, e := range r.Expressions {
		dlExpressions[i] = e.convert(symbols)
	}

	var scopes []datalog.Scope
	if r.Scopes != nil && len(r.Scopes) > 0 {
		scopes = make([]datalog.Scope, len(r.Scopes))
		for i, scope := range r.Scopes {
			scopes[i] = scope.convert(publicKeys)
		}
	}

	return datalog.Rule{
		Head:        r.Head.convert(symbols),
		Body:        dlBody,
		Expressions: dlExpressions,
		Scopes:      scopes,
	}
}

func (r Rule) Compare(r2 Rule) int {
	if x := r.Head.Compare(r2.Head); x != 0 {
		return x
	}
	if x := set.ComparedSlices(r.Body, r2.Body); x != 0 {
		return x
	}
	if x := set.ComparedSlices(r.Expressions, r2.Expressions); x != 0 {
		return x
	}
	if x := set.ComparedSlices(r.Scopes, r2.Scopes); x != 0 {
		return x
	}

	return 0
}

var _ set.Ordered[Rule] = (*Rule)(nil)

func fromDatalogRule(symbols *datalog.SymbolTable, publicKeys *datalog.PublicKeyTable, dlRule datalog.Rule) (*Rule, error) {
	head, err := fromDatalogPredicate(symbols, dlRule.Head)
	if err != nil {
		return nil, fmt.Errorf("failed to convert datalog rule head: %v", err)
	}

	body := make([]Predicate, len(dlRule.Body))
	for i, dlPred := range dlRule.Body {
		pred, err := fromDatalogPredicate(symbols, dlPred)
		if err != nil {
			return nil, fmt.Errorf("failed to convert datalog rule body: %v", err)
		}
		body[i] = *pred
	}

	expressions := make([]Expression, len(dlRule.Expressions))
	for i, dlExpr := range dlRule.Expressions {
		expr, err := fromDatalogExpression(symbols, dlExpr)
		if err != nil {
			return nil, fmt.Errorf("failed to convert datalog rule expression: %v", err)
		}
		expressions[i] = expr
	}

	var scopes []Scope
	if len(dlRule.Scopes) > 0 {
		scopes = make([]Scope, len(dlRule.Scopes))
		for i, dlScope := range dlRule.Scopes {
			scope, err := fromDatalogScope(publicKeys, dlScope)
			if err != nil {
				return nil, fmt.Errorf("failed to convert datalog rule scope: %w", err)
			}
			scopes[i] = *scope
		}
	}

	result := &Rule{
		Head:        *head,
		Body:        body,
		Expressions: expressions,
		Scopes:      scopes,
	}

	return result, nil
}

type Expression []Op

func (e Expression) convert(symbols *datalog.SymbolTable) datalog.Expression {
	expr := make(datalog.Expression, len(e))
	for i, elt := range e {
		expr[i] = elt.convert(symbols)
	}
	return expr
}

func (e Expression) Compare(e2 Expression) int {
	return set.ComparedSlices(e, e2)
}

var _ set.Ordered[Expression] = (*Expression)(nil)

func fromDatalogExpression(symbols *datalog.SymbolTable, dlExpr datalog.Expression) (Expression, error) {
	expr := make(Expression, len(dlExpr))
	for i, dlOP := range dlExpr {
		switch dlOP.Type() {
		case datalog.OpTypeValue:
			v, err := fromDatalogValueOp(symbols, dlOP.(datalog.Value))
			if err != nil {
				return nil, fmt.Errorf("failed to convert datalog expression value: %w", err)
			}
			expr[i] = v
		case datalog.OpTypeUnary:
			u, err := fromDatalogUnaryOp(symbols, dlOP.(datalog.UnaryOp))
			if err != nil {
				return nil, fmt.Errorf("failed to convert datalog unary expression: %w", err)
			}
			expr[i] = u
		case datalog.OpTypeBinary:
			b, err := fromDatalogBinaryOp(symbols, dlOP.(datalog.BinaryOp))
			if err != nil {
				return nil, fmt.Errorf("failed to convert datalog binary expression: %w", err)
			}
			expr[i] = b
		default:
			return nil, fmt.Errorf("unsupported datalog expression type: %v", dlOP.Type())
		}
	}
	return expr, nil
}

type Op interface {
	set.Ordered[Op]
	Type() OpType
	convert(symbols *datalog.SymbolTable) datalog.Op
}

type OpType byte

const (
	OpTypeValue OpType = iota
	OpTypeUnary
	OpTypeBinary
)

type Value struct {
	Term Term
}

func (v Value) Type() OpType {
	return OpTypeValue
}
func (v Value) convert(symbols *datalog.SymbolTable) datalog.Op {
	return datalog.Value{ID: v.Term.convert(symbols)}
}

func (v Value) Compare(op Op) int {
	if x := cmp.Compare(v.Type(), op.Type()); x != 0 {
		return x
	}
	if v2, ok := op.(Value); ok {
		return v.Term.Compare(v2.Term)
	}
	return 0 // We shouldn't get here
}

var _ Op = (*Value)(nil)

func fromDatalogValueOp(symbols *datalog.SymbolTable, dlValue datalog.Value) (Op, error) {
	term, err := fromDatalogID(symbols, dlValue.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to convert datalog expression value: %v", err)
	}
	return Value{Term: term}, nil
}

type unaryOpType byte

type UnaryOp unaryOpType

const (
	UnaryUndefined UnaryOp = iota
	UnaryNegate
	UnaryParens
	UnaryLength
)

func (UnaryOp) Type() OpType {
	return OpTypeUnary
}

func (u UnaryOp) convert(_ *datalog.SymbolTable) datalog.Op {
	switch u {
	case UnaryNegate:
		return datalog.UnaryOp{UnaryOpFunc: datalog.Negate{}}
	case UnaryParens:
		return datalog.UnaryOp{UnaryOpFunc: datalog.Parens{}}
	case UnaryLength:
		return datalog.UnaryOp{UnaryOpFunc: datalog.Length{}}
	default:
		panic(fmt.Sprintf("biscuit: cannot convert invalid unary op type: %v", u))
	}
}

func (u UnaryOp) Compare(op Op) int {
	if x := cmp.Compare(u.Type(), op.Type()); x != 0 {
		return x
	}
	if u2, ok := op.(UnaryOp); ok {
		if x := cmp.Compare(byte(u), byte(u2)); x != 0 {
			return x
		}
	}
	return 0 // We shouldn't get here
}

var _ Op = (*UnaryOp)(nil)

func fromDatalogUnaryOp(_ *datalog.SymbolTable, dlUnary datalog.UnaryOp) (Op, error) {
	switch dlUnary.UnaryOpFunc.Type() {
	case datalog.UnaryNegate:
		return UnaryNegate, nil
	case datalog.UnaryParens:
		return UnaryParens, nil
	case datalog.UnaryLength:
		return UnaryLength, nil
	default:
		return UnaryUndefined, fmt.Errorf("unsupported datalog unary op: %v", dlUnary.UnaryOpFunc.Type())
	}
}

type binaryOpType byte

type BinaryOp binaryOpType

const (
	BinaryUndefined BinaryOp = iota
	BinaryLessThan
	BinaryLessOrEqual
	BinaryGreaterThan
	BinaryGreaterOrEqual
	BinaryEqual
	BinaryContains
	BinaryPrefix
	BinarySuffix
	BinaryRegex
	BinaryAdd
	BinarySub
	BinaryMul
	BinaryDiv
	BinaryAnd
	BinaryOr
	BinaryIntersection
	BinaryUnion
)

func (BinaryOp) Type() OpType {
	return OpTypeBinary
}

func (b BinaryOp) convert(_ *datalog.SymbolTable) datalog.Op {
	switch b {
	case BinaryLessThan:
		return datalog.BinaryOp{BinaryOpFunc: datalog.LessThan{}}
	case BinaryLessOrEqual:
		return datalog.BinaryOp{BinaryOpFunc: datalog.LessOrEqual{}}
	case BinaryGreaterThan:
		return datalog.BinaryOp{BinaryOpFunc: datalog.GreaterThan{}}
	case BinaryGreaterOrEqual:
		return datalog.BinaryOp{BinaryOpFunc: datalog.GreaterOrEqual{}}
	case BinaryEqual:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Equal{}}
	case BinaryContains:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Contains{}}
	case BinaryPrefix:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Prefix{}}
	case BinarySuffix:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Suffix{}}
	case BinaryRegex:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Regex{}}
	case BinaryAdd:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Add{}}
	case BinarySub:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Sub{}}
	case BinaryMul:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Mul{}}
	case BinaryDiv:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Div{}}
	case BinaryAnd:
		return datalog.BinaryOp{BinaryOpFunc: datalog.And{}}
	case BinaryOr:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Or{}}
	case BinaryIntersection:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Intersection{}}
	case BinaryUnion:
		return datalog.BinaryOp{BinaryOpFunc: datalog.Union{}}
	default:
		panic(fmt.Sprintf("biscuit: cannot Convert invalid binary op type: %v", b))
	}
}

func (b BinaryOp) Compare(op Op) int {
	if x := cmp.Compare(b.Type(), op.Type()); x != 0 {
		return x
	}
	if b2, ok := op.(BinaryOp); ok {
		if x := cmp.Compare(byte(b), byte(b2)); x != 0 {
			return x
		}
	}
	return 0 // We shouldn't get here
}

var _ Op = (*BinaryOp)(nil)

func fromDatalogBinaryOp(_ *datalog.SymbolTable, dbBinary datalog.BinaryOp) (Op, error) {
	switch dbBinary.BinaryOpFunc.Type() {
	case datalog.BinaryLessThan:
		return BinaryLessThan, nil
	case datalog.BinaryLessOrEqual:
		return BinaryLessOrEqual, nil
	case datalog.BinaryGreaterThan:
		return BinaryGreaterThan, nil
	case datalog.BinaryGreaterOrEqual:
		return BinaryGreaterOrEqual, nil
	case datalog.BinaryEqual:
		return BinaryEqual, nil
	case datalog.BinaryContains:
		return BinaryContains, nil
	case datalog.BinaryPrefix:
		return BinaryPrefix, nil
	case datalog.BinarySuffix:
		return BinarySuffix, nil
	case datalog.BinaryRegex:
		return BinaryRegex, nil
	case datalog.BinaryAdd:
		return BinaryAdd, nil
	case datalog.BinarySub:
		return BinarySub, nil
	case datalog.BinaryMul:
		return BinaryMul, nil
	case datalog.BinaryDiv:
		return BinaryDiv, nil
	case datalog.BinaryAnd:
		return BinaryAnd, nil
	case datalog.BinaryOr:
		return BinaryOr, nil
	case datalog.BinaryIntersection:
		return BinaryIntersection, nil
	case datalog.BinaryUnion:
		return BinaryUnion, nil
	default:
		return BinaryUndefined, fmt.Errorf("unsupported datalog binary op: %v", dbBinary.BinaryOpFunc.Type())
	}
}

type CheckKind uint8

const (
	CheckOne CheckKind = iota
	CheckAll
	CheckReject
)

type Check struct {
	Queries []Rule
	Kind    CheckKind
}

func (c Check) Convert(
	symbols *datalog.SymbolTable,
	publicKeys *datalog.PublicKeyTable,
) datalog.Check {
	queries := make([]datalog.Rule, len(c.Queries))
	for i, q := range c.Queries {
		queries[i] = q.Convert(symbols, publicKeys)
	}

	var kind datalog.CheckKind
	switch c.Kind {
	case CheckAll:
		kind = datalog.CheckAll
	case CheckReject:
		kind = datalog.CheckReject
	case CheckOne:
		fallthrough
	default:
		kind = datalog.CheckOne
	}

	return datalog.Check{
		Queries: queries,
		Kind:    kind,
	}
}

func (c Check) Compare(c2 Check) int {
	return set.ComparedSlices(c.Queries, c2.Queries)
}

var _ set.Ordered[Check] = (*Check)(nil)

func fromDatalogCheck(symbols *datalog.SymbolTable, publicKeys *datalog.PublicKeyTable, dlCheck datalog.Check) (*Check, error) {
	queries := make([]Rule, len(dlCheck.Queries))
	for i, q := range dlCheck.Queries {
		query, err := fromDatalogRule(symbols, publicKeys, q)
		if err != nil {
			return nil, fmt.Errorf("failed to convert datalog check query: %w", err)
		}
		queries[i] = *query
	}

	var kind CheckKind
	switch dlCheck.Kind {
	case datalog.CheckAll:
		kind = CheckAll
	case datalog.CheckReject:
		kind = CheckReject
	case datalog.CheckOne:
		fallthrough
	default:
		kind = CheckOne
	}

	return &Check{
		Queries: queries,
		Kind:    kind,
	}, nil
}

type Predicate struct {
	Name string
	IDs  []Term
}

func (p Predicate) convert(symbols *datalog.SymbolTable) datalog.Predicate {
	ids := make([]datalog.Term, len(p.IDs))
	for i, a := range p.IDs {
		ids[i] = a.convert(symbols)
	}

	return datalog.Predicate{
		Name:  symbols.Insert(p.Name),
		Terms: ids,
	}
}
func (p Predicate) String() string {
	terms := make([]string, len(p.IDs))
	for i, a := range p.IDs {
		terms[i] = a.String()
	}
	return fmt.Sprintf("%s(%s)", p.Name, strings.Join(terms, ", "))
}

func (p Predicate) Compare(other Predicate) int {
	if i := cmp.Compare(p.Name, other.Name); i != 0 {
		return i
	}
	if i := cmp.Compare(len(p.IDs), len(other.IDs)); i != 0 {
		return i
	}
	for index := range p.IDs {
		if i := p.IDs[index].Compare(other.IDs[index]); i != 0 {
			return i
		}
	}
	return 0
}

func (p Predicate) Hash(builder *set.HashBuilder) *set.HashBuilder {
	builder = builder.String(p.Name)
	for _, id := range p.IDs {
		builder = builder.Hashable(id)
	}
	return builder
}

var _ set.Hashable[Predicate] = (*Predicate)(nil)

type TermType byte

const (
	TermTypeSymbol TermType = iota
	TermTypeVariable
	TermTypeInteger
	TermTypeString
	TermTypeDate
	TermTypeBytes
	TermTypeBool
	TermTypeSet
)

type Term interface {
	set.Hashable[Term]
	Type() TermType
	String() string
	convert(symbols *datalog.SymbolTable) datalog.Term
	Compare(Term) int
	Equal(Term) bool
}

type Variable string

func (a Variable) Type() TermType { return TermTypeVariable }
func (a Variable) convert(symbols *datalog.SymbolTable) datalog.Term {
	return datalog.Variable(symbols.Insert(string(a)))
}
func (a Variable) String() string { return fmt.Sprintf("$%s", string(a)) }

func (a Variable) Compare(other Term) int {
	if other == nil {
		return 1
	}
	if x := cmp.Compare(a.Type(), other.Type()); x != 0 {
		return x
	}
	if other2, ok := other.(Variable); ok {
		return strings.Compare(string(a), string(other2))
	}
	return 0
}

func (a Variable) Equal(other Term) bool {
	return a.Compare(other) == 0
}

func (a Variable) Hash(builder *set.HashBuilder) *set.HashBuilder {
	return builder.
		Byte(byte(a.Type())).
		String(a.String())
}

type Integer int64

func (a Integer) Type() TermType { return TermTypeInteger }
func (a Integer) convert(_ *datalog.SymbolTable) datalog.Term {
	return datalog.Integer(a)
}
func (a Integer) String() string { return fmt.Sprintf("%d", a) }

func (a Integer) Compare(other Term) int {
	if other == nil {
		return 1
	}
	if x := cmp.Compare(a.Type(), other.Type()); x != 0 {
		return x
	}
	if other2, ok := other.(Integer); ok {
		return cmp.Compare(a, other2)
	}
	return 0
}

func (a Integer) Equal(other Term) bool {
	return a.Compare(other) == 0
}

func (a Integer) Hash(builder *set.HashBuilder) *set.HashBuilder {
	return builder.
		Byte(byte(a.Type())).
		Int64(int64(a))
}

type String string

func (a String) Type() TermType { return TermTypeString }
func (a String) convert(symbols *datalog.SymbolTable) datalog.Term {
	return datalog.String(symbols.Insert(string(a)))
}
func (a String) String() string { return fmt.Sprintf("\"%s\"", string(a)) }

func (a String) Compare(other Term) int {
	if other == nil {
		return 1
	}
	if x := cmp.Compare(a.Type(), other.Type()); x != 0 {
		return x
	}
	if other2, ok := other.(String); ok {
		return strings.Compare(string(a), string(other2))
	}
	return 0
}

func (a String) Equal(other Term) bool {
	return a.Compare(other) == 0
}

func (a String) Hash(builder *set.HashBuilder) *set.HashBuilder {
	return builder.
		Byte(byte(a.Type())).
		String(string(a))
}

type Date time.Time

func (a Date) Type() TermType { return TermTypeDate }
func (a Date) convert(_ *datalog.SymbolTable) datalog.Term {
	return datalog.Date(time.Time(a).Unix())
}
func (a Date) String() string { return time.Time(a).UTC().Format(time.RFC3339) }

func (a Date) Compare(other Term) int {
	if other == nil {
		return 1
	}
	if x := cmp.Compare(a.Type(), other.Type()); x != 0 {
		return x
	}
	if other2, ok := other.(Date); ok {
		return time.Time(a).Compare(time.Time(other2))
	}
	return 0
}

func (a Date) Equal(other Term) bool {
	return a.Compare(other) == 0
}

func (a Date) Hash(builder *set.HashBuilder) *set.HashBuilder {
	return builder.
		Byte(byte(a.Type())).
		Int64(time.Time(a).UnixNano())
}

type Bytes []byte

func (a Bytes) Type() TermType { return TermTypeBytes }
func (a Bytes) convert(_ *datalog.SymbolTable) datalog.Term {
	return datalog.Bytes(a)
}
func (a Bytes) String() string { return fmt.Sprintf("hex:%s", hex.EncodeToString(a)) }

func (a Bytes) Compare(other Term) int {
	if other == nil {
		return 1
	}
	if x := cmp.Compare(a.Type(), other.Type()); x != 0 {
		return x
	}
	if other2, ok := other.(Bytes); ok {
		return bytes.Compare(a, other2)
	}
	return 0
}

func (a Bytes) Equal(other Term) bool {
	return a.Compare(other) == 0
}

func (a Bytes) Hash(builder *set.HashBuilder) *set.HashBuilder {
	return builder.
		Byte(byte(a.Type())).
		Bytes(a)
}

type Bool bool

func (b Bool) Type() TermType { return TermTypeBool }
func (b Bool) convert(_ *datalog.SymbolTable) datalog.Term {
	return datalog.Bool(b)
}
func (b Bool) String() string { return fmt.Sprintf("%t", b) }

func (b Bool) Compare(other Term) int {
	if other == nil {
		return 1
	}
	if x := cmp.Compare(b.Type(), other.Type()); x != 0 {
		return x
	}
	if other2, ok := other.(Bool); ok {
		return set.CompareBool(bool(b), bool(other2))
	}
	return 0
}

func (b Bool) Equal(other Term) bool {
	return b.Compare(other) == 0
}

func (b Bool) Hash(builder *set.HashBuilder) *set.HashBuilder {
	return builder.
		Byte(byte(b.Type())).
		Bool(bool(b))
}

type Set struct {
	*set.HashSet[Term]
}

func NewSet(terms ...Term) *Set {
	return &Set{set.NewHashSet[Term](terms...)}
}

func (a Set) Type() TermType { return TermTypeSet }

func (a Set) convert(symbols *datalog.SymbolTable) datalog.Term {
	datalogSet := datalog.NewSet()
	for e := range a.Iter() {
		datalogSet.Insert(e.convert(symbols))
	}
	return datalogSet
}

func (a Set) String() string {
	elts := make([]string, a.Size())
	{
		indx := 0
		for e := range a.Iter() {
			elts[indx] = e.String()
			indx++
		}
	}

	sort.Strings(elts)
	return fmt.Sprintf("{%s}", strings.Join(elts, ", "))
}

func (a Set) Compare(other Term) int {
	if other == nil {
		return 1
	}
	if x := cmp.Compare(a.Type(), other.Type()); x != 0 {
		return x
	}
	if b, canIter := other.(interface{ Iter() iter.Seq[Term] }); canIter {
		if x := set.Compared(a.Iter(), b.Iter()); x != 0 {
			return x
		}
	} else {
		return cmp.Compare(a.Size(), 0) // This shouldn't happen
	}

	return 0
}

func (a Set) Equal(other Term) bool {
	return a.Compare(other) == 0
}

func (a Set) Hash(builder *set.HashBuilder) *set.HashBuilder {
	builder = builder.Byte(byte(a.Type()))
	for term := range a.Iter() {
		builder = builder.Hashable(term)
	}
	return builder
}

type PolicyKind byte

const (
	PolicyKindAllow = iota
	PolicyKindDeny
)

var (
	// DefaultAllowPolicy allows the biscuit to verify sucessfully as long as all its checks generate some facts.
	DefaultAllowPolicy = Policy{Kind: PolicyKindAllow, Queries: []Rule{{Head: Predicate{Name: "allow"}}}}
	// DefaultDenyPolicy makes the biscuit verification fail in all cases.
	DefaultDenyPolicy = Policy{Kind: PolicyKindDeny, Queries: []Rule{{Head: Predicate{Name: "deny"}}}}
)

type Policy struct {
	Queries []Rule
	Kind    PolicyKind
}
