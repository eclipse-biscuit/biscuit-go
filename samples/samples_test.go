package biscuittest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/eclipse-biscuit/biscuit-go/v2/datalog"
	"github.com/eclipse-biscuit/biscuit-go/v2/parser"
)

type Samples struct {
	RootPrivateKey string     `json:"root_private_key"`
	RootPublicKey  string     `json:"root_public_key"`
	TestCases      []TestCase `json:"testcases"`
}

type TestCase struct {
	Title       string                `json:"title"`
	Filename    string                `json:"filename"`
	Token       []Block               `json:"token"`
	Validations map[string]Validation `json:"validations"`
}

type Block struct {
	Symbols     []string `json:"symbols"`
	PublicKeys  []any    `json:"public_keys"`
	ExternalKey any      `json:"external_key"`
	Code        string   `json:"code"`
}

type Result struct {
	Ok  *int          `json:"Ok"`
	Err *BiscuitError `json:"Err"`
}

type BiscuitError struct {
	FailedLogic *struct {
		Unauthorized *struct {
			Policy struct {
				Allow int `json:"Allow"`
			} `json:"policy"`
			Checks []struct {
				Block struct {
					BlockID int    `json:"block_id"`
					CheckID int    `json:"check_id"`
					Rule    string `json:"rule"`
				} `json:"Block"`
			} `json:"checks"`
		} `json:"Unauthorized"`
		InvalidBlockRule []any `json:"InvalidBlockRule"`
	} `json:"FailedLogic"`
	Format *struct {
		Signature *struct {
			InvalidSignature string `json:"InvalidSignature"`
		} `json:"Signature"`
	} `json:"Format"`
}

type World struct {
	Facts    []Facts  `json:"facts"`
	Rules    []Rules  `json:"rules"`
	Checks   []Checks `json:"checks"`
	Policies []string `json:"policies"`
}

type Facts struct {
	Origin []*uint64 `json:"origin"` // Can be null
	Facts  []string  `json:"facts"`
}

type Rules struct {
	Origin *uint64  `json:"origin"` // Can be null
	Rules  []string `json:"rules"`
}

type Checks struct {
	Origin *uint64  `json:"origin"` // Can be null
	Checks []string `json:"checks"`
}

type Validation struct {
	World          World    `json:"world"`
	Result         Result   `json:"result"`
	AuthorizerCode string   `json:"authorizer_code"`
	RevocationIds  []string `json:"revocation_ids"`
}

// extractWorld gets data out of the authorizer for comparison to a [World] in tests.
func extractWorld(t *testing.T, authorizer biscuit.Authorizer) World {
	t.Helper()
	world := World{}

	err := biscuit.InspectAuthorizer(authorizer, func(inspector biscuit.AuthorizerInspector) {
		// Build symbol and public key tables once from the authorizer
		symbols := datalog.SymbolTable{}
		for sym := range inspector.Symbols() {
			symbols = append(symbols, sym)
		}

		pubKeys := datalog.PublicKeyTable{}
		for pk := range inspector.PublicKeys() {
			pubKeys = append(pubKeys, pk)
		}

		debug := datalog.SymbolDebugger{
			SymbolTable:    &symbols,
			PublicKeyTable: &pubKeys,
		}

		world.Facts = make([]Facts, 0)
		for blockIDs, biscuitFacts := range inspector.Facts() {
			var reportOrigins []*uint64
			if len(blockIDs) > 0 {
				reportOrigins = make([]*uint64, 0, len(blockIDs))
				for _, blockID := range blockIDs {
					if blockID == datalog.AuthorizerBlockID {
						reportOrigins = append(reportOrigins, nil)
					} else {
						clonedID := blockID
						reportOrigins = append(reportOrigins, &clonedID)
					}
				}
			}

			reportFacts := make([]string, 0, len(biscuitFacts))
			for _, biscuitFact := range biscuitFacts {
				reportFacts = append(reportFacts, biscuitFact.String())
			}
			sort.Strings(reportFacts)

			world.Facts = append(world.Facts, Facts{
				Origin: reportOrigins,
				Facts:  reportFacts,
			})
		}

		world.Rules = make([]Rules, 0)
		for blockID, rules := range inspector.Rules() {
			var reportOrigin *uint64
			if blockID != datalog.AuthorizerBlockID {
				clonedID := blockID
				reportOrigin = &clonedID
			}

			reportRules := make([]string, 0, len(rules))
			for _, biscuitRule := range rules {
				dlRule := biscuitRule.Convert(&symbols, &pubKeys)
				reportRules = append(reportRules, debug.Rule(dlRule))
			}
			sort.Strings(reportRules)

			world.Rules = append(world.Rules, Rules{
				Origin: reportOrigin,
				Rules:  reportRules,
			})
		}

		world.Checks = make([]Checks, 0)
		for blockID, checks := range inspector.Checks() {
			clonedID := blockID
			reportOrigin := &clonedID

			reportChecks := make([]string, 0, len(checks))
			for _, biscuitCheck := range checks {
				dlCheck := biscuitCheck.Convert(&symbols, &pubKeys)
				reportChecks = append(reportChecks, debug.Check(dlCheck))
			}
			sort.Strings(reportChecks)

			world.Checks = append(world.Checks, Checks{
				Origin: reportOrigin,
				Checks: reportChecks,
			})
		}

		// TODO - Support comparing policies.
		world.Policies = []string{}
	})
	require.NoError(t, err)

	return world
}

// All tests below this number are enabled
const skipTestsAtNum int = 26

// These tests are above `skipTestsAtNum` and are also enabled
var allowTheseTests = []int{29, 36}

func CheckSample(rootKey ed25519.PublicKey, c TestCase, t *testing.T) {
	t.Helper()

	// Skip tests for block versions not yet supported
	testNum := 0
	if _, err := fmt.Sscanf(c.Filename, "test%d_", &testNum); err == nil {
		if testNum >= skipTestsAtNum && !slices.Contains(allowTheseTests, testNum) {
			t.SkipNow()
		}
	}

	b, err := os.ReadFile("./data/current/" + c.Filename)
	require.NoError(t, err)
	token, err := biscuit.Unmarshal(b)

	if err == nil {
		// this sample uses a tampered biscuit file on purpose
		if c.Filename != "test006_reordered_blocks.bc" {
			CompareBlocks(*token, c.Token, t)
		}

		for _, v := range c.Validations {
			CompareResult(rootKey, c.Filename, *token, v, t)
		}

	} else {
		for _, v := range c.Validations {
			require.Nil(t, v.Result.Ok)
		}
	}
}

func CompareBlocks(biscuitUnderTest biscuit.Biscuit, inputBlocks []Block, t *testing.T) {
	t.Helper()

	sample := biscuitUnderTest.Code()

	p := parser.New()

	rng := rand.Reader
	_, privateRoot, _ := ed25519.GenerateKey(rng)
	authority, err := p.Block(inputBlocks[0].Code, nil)
	require.NoError(t, err)
	builder := biscuit.NewBuilder(privateRoot)
	err = builder.AddBlock(authority)
	require.NoError(t, err)
	authorityBiscuit, err := builder.Build()
	require.NoError(t, err)

	prevBiscuit := *authorityBiscuit
	for i, inputBlock := range inputBlocks[1:] {
		blockID := uint64(i + 1)
		parsedBlock, err := p.Block(inputBlock.Code, nil)
		require.NoError(t, err)
		builder := prevBiscuit.CreateBlock(blockID)
		err = builder.AddBlock(parsedBlock)
		require.NoError(t, err)
		resultBiscuit, err := prevBiscuit.AppendBlock(rng, builder)
		require.NoError(t, err)
		prevBiscuit = *resultBiscuit
	}

	require.Equal(t, sample, prevBiscuit.Code())
}

func CompareResult(root_key ed25519.PublicKey, filename string, biscuitUnderTest biscuit.Biscuit, v Validation, t *testing.T) {
	t.Helper()

	p := parser.New()
	parsedAuthorizer, err := p.Authorizer(v.AuthorizerCode, nil)
	require.NoError(t, err)
	authorizerBuilder, err := biscuitUnderTest.Authorizer(root_key)

	if err != nil {
		CompareError(err, v.Result.Err, t)
	} else {
		authorizerBuilder.AddAuthorizer(parsedAuthorizer)
		authorizer, err := authorizerBuilder.Build()
		require.NoError(t, err)

		err = authorizer.Authorize()
		if v.Result.Err != nil {
			require.Error(t, err)
			CompareError(err, v.Result.Err, t)
		} else {
			require.NoError(t, err)
			require.NotNil(t, v.Result.Ok)
		}
		// Only compare world if it's not null (all fields are nil means it was null in JSON)
		if v.World.Facts != nil || v.World.Rules != nil || v.World.Checks != nil || v.World.Policies != nil {
			require.Empty(t,
				cmp.Diff(
					v.World,
					extractWorld(t, authorizer),
					// TODO: Support comparing policies (need to convert [biscuit.Policy] into a string).
					cmpopts.IgnoreFields(World{}, "Policies"),
				),
				"datalog worlds should be equal",
			)
		}
	}
}

func CompareError(authorizationError error, sampleError *BiscuitError, t *testing.T) {
	t.Helper()

	require.Error(t, authorizationError)
	require.NotNil(t, sampleError)

	error_string := authorizationError.Error()
	if sampleError.Format != nil {
		require.True(t, strings.Contains(error_string, "biscuit: invalid signature"))
	} else if sampleError.FailedLogic != nil {
		if sampleError.FailedLogic.Unauthorized != nil {
			// todo check the block and check ids (if there is a single failed check, because the lib only reports one)
			require.Regexp(t, "^biscuit: verification failed: failed to verify", error_string)
		} else if sampleError.FailedLogic.InvalidBlockRule != nil {
			// todo extract the block number
			require.Regexp(t, "^biscuit: verification failed: failed to verify", error_string)
		} else {
			require.Fail(t, error_string)
		}
	} else {
		require.Fail(t, error_string)
	}
}

func TestReadSamples(t *testing.T) {
	t.Helper()

	b, err := os.ReadFile("./data/current/samples.json")
	require.NoError(t, err)
	var samples Samples
	err = json.Unmarshal(b, &samples)
	require.NoError(t, err)

	root_key, err := hex.DecodeString(samples.RootPublicKey)
	require.NoError(t, err)
	for _, v := range samples.TestCases {
		t.Run(v.Filename, func(t *testing.T) { CheckSample(root_key, v, t) })
	}

}
