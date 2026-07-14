package biscuit

import (
	"errors"
	"fmt"
	"google.golang.org/protobuf/proto"

	"github.com/eclipse-biscuit/biscuit-go/v2/datalog"
	"github.com/eclipse-biscuit/biscuit-go/v2/pb"
)

const (
	authorizerName = "authorizer"
)

var (
	ErrMissingSymbols   = errors.New("biscuit: missing symbols")
	ErrPolicyDenied     = errors.New("biscuit: denied by policy")
	ErrNoMatchingPolicy = errors.New("biscuit: denied by no matching policies")
)

type AuthorizerBuilder interface {
	AddAuthorizer(ParsedAuthorizer)
	AddBlock(ParsedBlock)
	AddPolicy(Policy)
	AddFact(Fact)
	AddScope(Scope)
	AddRule(Rule)
	AddCheck(Check)

	SerializePolicies() ([]byte, error)
	LoadPolicies([]byte) error

	Build(...AuthorizerOption) (Authorizer, error)
}

type Authorizer interface {
	Authorize() error
	Query(rule Rule) (FactSet, error)
	Biscuit() *Biscuit

	PrintWorld() string
}

type authorizerBuilder struct {
	biscuit *Biscuit

	authorizerFacts    []Fact
	authorizerRules    []Rule
	authorizerScopes   []Scope
	authorizerChecks   []Check
	authorizerPolicies []Policy
}

var _ AuthorizerBuilder = (*authorizerBuilder)(nil)

func NewAuthorizerBuilder(biscuit *Biscuit) AuthorizerBuilder {
	return &authorizerBuilder{
		biscuit:            biscuit,
		authorizerFacts:    make([]Fact, 0),
		authorizerRules:    make([]Rule, 0),
		authorizerScopes:   make([]Scope, 0),
		authorizerChecks:   make([]Check, 0),
		authorizerPolicies: make([]Policy, 0),
	}
}

func (ab *authorizerBuilder) AddAuthorizer(a ParsedAuthorizer) {
	ab.AddBlock(a.Block)

	for _, p := range a.Policies {
		ab.AddPolicy(p)
	}
}

func (ab *authorizerBuilder) AddBlock(block ParsedBlock) {
	for fact := range block.Facts.Iter() {
		ab.AddFact(fact)
	}

	for _, rule := range block.Rules {
		ab.AddRule(rule)
	}

	for _, check := range block.Checks {
		ab.AddCheck(check)
	}

	for _, scope := range block.Scope {
		ab.AddScope(scope)
	}
}

func (ab *authorizerBuilder) AddFact(fact Fact) {
	ab.authorizerFacts = append(ab.authorizerFacts, fact)
}

func (ab *authorizerBuilder) AddCheck(check Check) {
	ab.authorizerChecks = append(ab.authorizerChecks, check)
}

func (ab *authorizerBuilder) AddPolicy(policy Policy) {
	ab.authorizerPolicies = append(ab.authorizerPolicies, policy)
}

func (ab *authorizerBuilder) AddScope(scope Scope) {
	ab.authorizerScopes = append(ab.authorizerScopes, scope)
}

func (ab *authorizerBuilder) AddRule(rule Rule) {
	ab.authorizerRules = append(ab.authorizerRules, rule)
}

func (ab *authorizerBuilder) SerializePolicies() ([]byte, error) {
	symbols := datalog.SymbolTable{}
	publicKeys := *datalog.NewPublicKeyTable()

	protoFacts := make([]*pb.FactV2, 0, len(ab.authorizerFacts))
	for _, fact := range ab.authorizerFacts {
		dlFact := fact.convert(&symbols)
		protoFact, err := tokenFactToProtoFactV2(dlFact)
		if err != nil {
			return nil, fmt.Errorf("%s: failed to Convert fact %v: %w", authorizerName, fact, err)
		}
		protoFacts = append(protoFacts, protoFact)
	}

	protoRules := make([]*pb.RuleV2, 0, len(ab.authorizerRules))
	for _, rule := range ab.authorizerRules {
		dlRule := rule.Convert(&symbols, &publicKeys)
		protoRule, err := tokenRuleToProtoRuleV2(dlRule)
		if err != nil {
			return nil, fmt.Errorf("%s: failed to Convert rule %v: %w", authorizerName, rule, err)
		}
		protoRules = append(protoRules, protoRule)
	}

	protoChecks := make([]*pb.CheckV2, 0, len(ab.authorizerChecks))
	for _, check := range ab.authorizerChecks {
		dlCheck := check.Convert(&symbols, &publicKeys)
		protoCheck, err := tokenCheckToProtoCheckV2(dlCheck)
		if err != nil {
			return nil, fmt.Errorf("%s: failed to Convert check %v: %w", authorizerName, check, err)
		}
		protoChecks = append(protoChecks, protoCheck)
	}

	protoPolicies := make([]*pb.Policy, 0, len(ab.authorizerPolicies))
	for _, policy := range ab.authorizerPolicies {
		protoPolicy := &pb.Policy{}
		switch policy.Kind {
		case PolicyKindAllow:
			kind := pb.Policy_Allow
			protoPolicy.Kind = &kind
		case PolicyKindDeny:
			kind := pb.Policy_Deny
			protoPolicy.Kind = &kind
		default:
			return nil, fmt.Errorf("%s: unsupported policy kind %v", authorizerName, policy.Kind)
		}

		protoPolicy.Queries = make([]*pb.RuleV2, 0, len(policy.Queries))
		for _, rule := range policy.Queries {
			protoRule, err := tokenRuleToProtoRuleV2(rule.Convert(&symbols, &publicKeys))
			if err != nil {
				return nil, fmt.Errorf("%s: failed to Convert policy rule: %w", authorizerName, err)
			}
			protoPolicy.Queries = append(protoPolicy.Queries, protoRule)
		}

		protoPolicies = append(protoPolicies, protoPolicy)
	}

	return proto.Marshal(&pb.AuthorizerPolicies{
		Symbols:  symbols,
		Version:  proto.Uint32(uint32(MaxSchemaVersion)),
		Facts:    protoFacts,
		Rules:    protoRules,
		Checks:   protoChecks,
		Policies: protoPolicies,
	})
}

func (ab *authorizerBuilder) LoadPolicies(authorizerPolicies []byte) error {
	pbPolicies := &pb.AuthorizerPolicies{}
	if err := proto.Unmarshal(authorizerPolicies, pbPolicies); err != nil {
		return fmt.Errorf("%s: failed to load authorizer policies: %w", authorizerName, err)
	}

	version := DatalogVersion(pbPolicies.GetVersion())

	if version < MinSchemaVersion || version > MaxSchemaVersion {
		return fmt.Errorf("%s: unsupported authorizerPolicies version %d", authorizerName, pbPolicies.GetVersion())
	}

	return ab.loadPoliciesV2(pbPolicies)
}

func (ab *authorizerBuilder) loadPoliciesV2(pbPolicies *pb.AuthorizerPolicies) error {
	// The serialized policies have their own symbol table
	policySymbolTable := datalog.SymbolTable(pbPolicies.Symbols)
	policyPublicKeys := *datalog.NewPublicKeyTable()

	// Load facts.
	for _, pbFact := range pbPolicies.Facts {
		dlFact, err := protoFactToTokenFactV2(pbFact)
		if err != nil {
			return fmt.Errorf("%s: load policies v2: failed to Convert fact: %w", authorizerName, err)
		}

		biscuitFact, err := fromDatalogFact(&policySymbolTable, *dlFact)
		if err != nil {
			return fmt.Errorf("%s: load policies v2: failed to Convert fact: %w", authorizerName, err)
		}
		ab.authorizerFacts = append(ab.authorizerFacts, *biscuitFact)
	}

	// Load Rules.
	for _, pbRule := range pbPolicies.Rules {
		dlRule, err := protoRuleToTokenRuleV2(pbRule)
		if err != nil {
			return fmt.Errorf("%s: load policies v1: failed to Convert rule: %w", authorizerName, err)
		}

		biscuitRule, err := fromDatalogRule(&policySymbolTable, &policyPublicKeys, *dlRule)
		if err != nil {
			return fmt.Errorf("%s: load policies v2: failed to Convert rule: %w", authorizerName, err)
		}
		ab.authorizerRules = append(ab.authorizerRules, *biscuitRule)
	}

	// Load Checks.
	for _, pbCheck := range pbPolicies.Checks {
		dlCheck, err := protoCheckToTokenCheckV2(pbCheck)
		if err != nil {
			return fmt.Errorf("%s: load policies v2: failed to Convert check: %w", authorizerName, err)
		}

		biscuitCheck, err := fromDatalogCheck(&policySymbolTable, &policyPublicKeys, *dlCheck)
		if err != nil {
			return fmt.Errorf("%s: load policies v2: failed to Convert check: %w", authorizerName, err)
		}
		ab.authorizerChecks = append(ab.authorizerChecks, *biscuitCheck)
	}

	// Load Policies.
	for _, pbPolicy := range pbPolicies.Policies {
		policy := Policy{}
		switch *pbPolicy.Kind {
		case pb.Policy_Allow:
			policy.Kind = PolicyKindAllow
		case pb.Policy_Deny:
			policy.Kind = PolicyKindDeny
		default:
			return fmt.Errorf("%s: load authorizerPolicies v1: unsupported proto policy kind %v", authorizerName, pbPolicy.Kind)
		}

		policy.Queries = make([]Rule, 0, len(pbPolicy.Queries))
		for _, pbRule := range pbPolicy.Queries {
			dlRule, err := protoRuleToTokenRuleV2(pbRule)
			if err != nil {
				return fmt.Errorf("%s: load authorizerPolicies v1: failed to Convert datalog policy rule: %w", authorizerName, err)
			}

			biscuitRule, err := fromDatalogRule(&policySymbolTable, &policyPublicKeys, *dlRule)
			if err != nil {
				return fmt.Errorf("%s: load authorizerPolicies v1: failed to Convert policy rule: %w", authorizerName, err)
			}
			policy.Queries = append(policy.Queries, *biscuitRule)
		}
		ab.authorizerPolicies = append(ab.authorizerPolicies, policy)
	}

	return nil
}

type authorizerBuilderConfig struct {
	world             *datalog.World
	symbols           *datalog.SymbolTable
	publicKeys        *datalog.PublicKeyTable
	signatureRegistry *datalog.SignatureRegistry
}

type AuthorizerOption func(*authorizerBuilderConfig)

func WithWorld(world *datalog.World) AuthorizerOption {
	return func(abc *authorizerBuilderConfig) {
		abc.world = world
	}
}

func WithSymbols(symbols *datalog.SymbolTable) AuthorizerOption {
	return func(abc *authorizerBuilderConfig) {
		abc.symbols = symbols
	}
}

func WithPublicKeys(publicKeys *datalog.PublicKeyTable) AuthorizerOption {
	return func(abc *authorizerBuilderConfig) {
		abc.publicKeys = publicKeys
	}
}

func (ab *authorizerBuilder) Build(opts ...AuthorizerOption) (Authorizer, error) {
	abc := authorizerBuilderConfig{
		symbols:           &datalog.SymbolTable{},
		publicKeys:        &datalog.PublicKeyTable{},
		signatureRegistry: &datalog.SignatureRegistry{},
		world:             &datalog.World{},
	}

	for _, opt := range opts {
		opt(&abc)
	}

	world := datalog.NewWorld()

	// Store the biscuit scopes and checks, by block ID, for later reference.
	// This is necessary because the world does not store block scopes or checks.
	biscuitScopes := make([][]datalog.Scope, 0, len(ab.biscuit.blocks)+1)
	biscuitChecks := make([][]datalog.Check, 0, len(ab.biscuit.blocks)+1)

	// Iterate over the biscuit blocks and populate the symbols table, public keys table,
	// and the signature registry.
	if ab.biscuit != nil {
		blockID := uint64(0)
		for block := range ab.biscuit.Blocks() {
			var blockSymbols *datalog.SymbolTable

			// Either use the block symbols (for 3rd party blocks) or the biscuit symbols.
			if blockID > 0 && block.IsThirdParty() {
				blockSymbols = block.symbols
				pkTableIndex := abc.publicKeys.Insert(block.externalSignature.publicKey)
				abc.signatureRegistry.Insert(pkTableIndex, datalog.BlockID(blockID))
			} else {
				blockSymbols = ab.biscuit.symbols
			}

			// Translate Scopes and save them for later.
			theseScopes := make([]datalog.Scope, 0, len(block.scopes))
			for _, dlScope := range block.scopes {
				// Hydrate the scope with biscuit's symbol table.
				biscuitScope, err := fromDatalogScope(block.publicKeys, dlScope)
				if err != nil {
					return nil, fmt.Errorf("%s: failed to convert scope %v: %w", authorizerName, dlScope, err)
				}
				theseScopes = append(theseScopes, biscuitScope.convert(abc.publicKeys))
			}
			// Save the scopes for later reference.
			biscuitScopes = append(biscuitScopes, theseScopes)

			// Insert Facts into the World
			{
				origin := *datalog.NewOrigin(blockID)
				for _, dlFact := range block.facts {
					// Hydrate the fact with the biscuit's symbol table.
					biscuitFact, err := fromDatalogFact(blockSymbols, dlFact)
					if err != nil {
						return nil, fmt.Errorf("%s: failed to Convert fact %v: %w", authorizerName, dlFact, err)
					}
					// Store the fact in the world with the new symbol table.
					world.AddFact(
						origin,
						biscuitFact.convert(abc.symbols),
					)
				}
			}

			// Insert Rules into the World
			for _, dlRule := range block.rules {
				// Hydrate the rule with the biscuit's symbol table.
				biscuitRule, err := fromDatalogRule(blockSymbols, block.publicKeys, dlRule)
				if err != nil {
					return nil, fmt.Errorf("%s: failed to Convert rule %v: %w", authorizerName, dlRule, err)
				}
				// Store the rule in the world with new symbol table.
				updatedDLRule := biscuitRule.Convert(abc.symbols, abc.publicKeys)
				world.AddRule(
					*datalog.NewTrustedOriginFromScopes(
						theseScopes,
						updatedDLRule.Scopes,
						blockID,
						*abc.signatureRegistry,
					),
					datalog.BlockID(blockID),
					updatedDLRule,
				)
			}

			// Translate Checks and save them for later.
			{
				theseChecks := make([]datalog.Check, 0, len(block.checks))
				for _, dlCheck := range block.checks {
					// Hydrate the check with biscuit's symbol table.
					biscuitCheck, err := fromDatalogCheck(blockSymbols, block.publicKeys, dlCheck)
					if err != nil {
						return nil, fmt.Errorf("%s: failed to Convert check %v: %w", authorizerName, dlCheck, err)
					}
					theseChecks = append(theseChecks, biscuitCheck.Convert(abc.symbols, abc.publicKeys))
				}
				// Save the checks for later reference.
				biscuitChecks = append(biscuitChecks, theseChecks)
			}

			blockID++
		}
	}

	// Get the authorizer scopes for inserting rules.
	authorizerScopes := make([]datalog.Scope, 0, len(ab.authorizerScopes))
	for _, scope := range ab.authorizerScopes {
		dlScope := scope.convert(abc.publicKeys)
		authorizerScopes = append(authorizerScopes, dlScope)
	}

	// Load authorizer facts into the world.
	{
		origin := datalog.NewOrigin(datalog.AuthorizerBlockID)
		for _, fact := range ab.authorizerFacts {
			dlFact := fact.convert(abc.symbols)
			world.AddFact(*origin, dlFact)
		}
	}

	// Load authorizer rules into the world.
	for _, rule := range ab.authorizerRules {
		dlRule := rule.Convert(abc.symbols, abc.publicKeys)
		world.AddRule(
			*datalog.NewTrustedOriginFromScopes(
				authorizerScopes,
				dlRule.Scopes,
				datalog.AuthorizerBlockID,
				*abc.signatureRegistry,
			),
			datalog.BlockID(datalog.AuthorizerBlockID),
			dlRule,
		)
	}

	// Get authorizer checks.
	authorizerChecks := make([]datalog.Check, 0, len(ab.authorizerChecks))
	for _, check := range ab.authorizerChecks {
		dlCheck := check.Convert(abc.symbols, abc.publicKeys)
		authorizerChecks = append(authorizerChecks, dlCheck)
	}

	return &authorizer{
		biscuit: ab.biscuit,
		world:   world,

		symbols:           abc.symbols,
		publicKeys:        abc.publicKeys,
		signatureRegistry: abc.signatureRegistry,

		authorizerScopes:   authorizerScopes,
		authorizerChecks:   authorizerChecks,
		authorizerPolicies: ab.authorizerPolicies,

		biscuitChecks: biscuitChecks,
		biscuitScopes: biscuitScopes,
	}, nil
}

type authorizer struct {
	biscuit *Biscuit
	world   *datalog.World

	symbols           *datalog.SymbolTable
	publicKeys        *datalog.PublicKeyTable
	signatureRegistry *datalog.SignatureRegistry

	authorizerScopes   []datalog.Scope
	authorizerChecks   []datalog.Check
	authorizerPolicies []Policy

	biscuitChecks [][]datalog.Check
	biscuitScopes [][]datalog.Scope
}

var _ Authorizer = (*authorizer)(nil)

// TODO - Cache execution results.
// TODO - Test what happens when `Authorize` is called more than once.

// Authorize executes the datalog [World] and runs checks and policies as verification.
func (v *authorizer) Authorize() error {
	if err := v.world.Run(v.symbols); err != nil {
		return err
	}

	// Note: errors returned by this method should start with "^biscuit: verification failed".
	// Errors accumulated in this array do not need to start with that prefix.
	var errs []error

	// Run authorizer checks.
	for i, dlCheck := range v.authorizerChecks {
		successful := false
		for _, query := range dlCheck.Queries {
			trustedOrigin := datalog.NewTrustedOriginFromScopes(
				v.authorizerScopes,
				query.Scopes,
				datalog.AuthorizerBlockID,
				*v.signatureRegistry,
			)
			facts, err := v.world.QueryRule(query, *trustedOrigin, v.symbols)
			if err != nil {
				return fmt.Errorf("biscuit: verification failed: Query %q failed: %s", query, err)
			}
			if len(facts) != 0 {
				successful = true
				break
			}
		}

		if !successful {
			debug := datalog.SymbolDebugger{
				SymbolTable:    v.symbols,
				PublicKeyTable: v.publicKeys,
			}
			errs = append(errs, fmt.Errorf("failed to verify authorizer check #%d: %s", i, debug.Check(dlCheck)))
		}
	}

	// Run biscuit checks (including the authority block).
	for i, checks := range v.biscuitChecks {
		blockID := uint64(i)
		for j, dlCheck := range checks {
			successful, err := dlCheck.Verify(
				v.world.Facts,
				v.biscuitScopes[i],
				blockID,
				*v.signatureRegistry,
				v.symbols,
			)
			if err != nil {
				return fmt.Errorf("biscuit: verification failed: Query %q failed: %s", checks[j], err)
			}

			if !successful {
				debug := datalog.SymbolDebugger{
					SymbolTable:    v.symbols,
					PublicKeyTable: v.publicKeys,
				}
				errs = append(errs, fmt.Errorf("failed to verify block %d check %d: %s", blockID, j, debug.Check(dlCheck)))
			}
		}

	}

	// Return an error if any checks failed
	if len(errs) > 0 {
		return fmt.Errorf("biscuit: verification failed: %w", errors.Join(errs...))
	}

	// All checks passed, now evaluate policies
	policyMatched := false
	policyResult := ErrPolicyDenied
	for _, policy := range v.authorizerPolicies {
		if policyMatched {
			break
		}
		for _, query := range policy.Queries {
			dlQuery := query.Convert(v.symbols, v.publicKeys)
			trustedOrigin := *datalog.NewTrustedOriginFromScopes(
				[]datalog.Scope{},
				dlQuery.Scopes,
				datalog.AuthorizerBlockID,
				*v.signatureRegistry,
			)
			res, err := v.world.QueryRule(
				dlQuery,
				trustedOrigin,
				v.symbols,
			)
			if err != nil {
				debug := datalog.SymbolDebugger{SymbolTable: v.symbols, PublicKeyTable: v.publicKeys}
				return fmt.Errorf("biscuit: verification failed: Query %s failed: %w", debug.Rule(dlQuery), err)
			}
			if len(res) != 0 {
				switch policy.Kind {
				case PolicyKindAllow:
					policyResult = nil
					policyMatched = true
				case PolicyKindDeny:
					policyResult = ErrPolicyDenied
					policyMatched = true
				}
				break
			}
		}
	}

	// Return policy result
	if policyMatched {
		return policyResult
	} else {
		return ErrNoMatchingPolicy
	}
}

func (v *authorizer) Query(rule Rule) (FactSet, error) {
	if err := v.world.Run(v.symbols); err != nil {
		return FactSet{}, err
	}

	convertedRule := rule.Convert(v.symbols, v.publicKeys)
	trustedOrigin := datalog.NewTrustedOriginFromScopes(
		[]datalog.Scope{},
		convertedRule.Scopes,
		datalog.AuthorizerBlockID,
		*v.signatureRegistry,
	)

	facts, err := v.world.QueryRule(
		convertedRule,
		*trustedOrigin,
		v.symbols,
	)
	if err != nil {
		return FactSet{}, err
	}

	result := *NewFactSet()
	for fact := range facts.AllFacts() {
		biscuitFact, err := fromDatalogFact(v.symbols, fact)
		if err != nil {
			return FactSet{}, err
		}

		result.Insert(*biscuitFact)
	}

	return result, nil
}

func (v *authorizer) Biscuit() *Biscuit {
	return v.biscuit
}

// PrintWorld returns the content of the Datalog environment
// This will be empty until the call to Authorize(), where
// facts, rules and authorizerChecks will be evaluated
func (v *authorizer) PrintWorld() string {
	debug := datalog.SymbolDebugger{
		SymbolTable:    v.symbols,
		PublicKeyTable: v.publicKeys,
	}

	return debug.World(v.world)
}
