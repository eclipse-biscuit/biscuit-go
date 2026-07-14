package biscuit

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/eclipse-biscuit/biscuit-go/v2/datalog"
	"github.com/eclipse-biscuit/biscuit-go/v2/internal/set"
)

func TestBiscuit(t *testing.T) {
	rng := rand.Reader
	const rootKeyID = 123
	const contextText = "current_context"
	publicRoot, privateRoot, _ := ed25519.GenerateKey(rng)

	builder := NewBuilder(
		privateRoot,
		WithRNG(rng),
		WithRootKeyID(rootKeyID))

	err := builder.AddAuthorityFact(Fact{
		Predicate: Predicate{Name: "right", IDs: []Term{String("/a/file1"), String("read")}},
	})
	require.NoError(t, err)
	err = builder.AddAuthorityFact(Fact{
		Predicate: Predicate{Name: "right", IDs: []Term{String("/a/file1"), String("write")}},
	})
	require.NoError(t, err)
	err = builder.AddAuthorityFact(Fact{
		Predicate: Predicate{Name: "right", IDs: []Term{String("/a/file2"), String("read")}},
	})
	require.NoError(t, err)

	builder.SetContext(contextText)

	biscuit1, err := builder.Build()
	require.NoError(t, err)
	require.EqualValues(t, contextText, biscuit1.GetContext(), "context authority")
	{
		keyID := biscuit1.RootKeyID()
		require.NotNil(t, keyID, "root key ID present")
		require.EqualValues(t, rootKeyID, *keyID, "root key ID")
	}

	biscuit1Ser, err := biscuit1.Serialize()
	require.NoError(t, err)
	require.NotEmpty(t, biscuit1Ser)

	biscuit1Deser, err := Unmarshal(biscuit1Ser)
	require.NoError(t, err)
	{
		keyID := biscuit1Deser.RootKeyID()
		require.NotNil(t, keyID, "root key ID present after round trip")
		require.EqualValues(t, rootKeyID, *keyID, "root key ID after round trip")
	}

	blockBuilder2 := biscuit1Deser.CreateBlock(1)
	err = blockBuilder2.AddCheck(Check{
		Queries: []Rule{
			{
				Head: Predicate{Name: "caveat", IDs: []Term{Variable("0")}},
				Body: []Predicate{
					{Name: "resource", IDs: []Term{Variable("0")}},
					{Name: "operation", IDs: []Term{String("read")}},
					{Name: "right", IDs: []Term{Variable("0"), String("read")}},
				},
			},
		},
	})
	require.NoError(t, err)

	biscuit2, err := biscuit1Deser.AppendBlock(rng, blockBuilder2)
	require.NoError(t, err)

	biscuit2Ser, err := biscuit2.Serialize()
	require.NoError(t, err)
	require.NotEmpty(t, biscuit2Ser)

	biscuit2Deser, err := Unmarshal(biscuit2Ser)
	require.NoError(t, err)

	blockBuilder3 := biscuit2Deser.CreateBlock(2)
	err = blockBuilder3.AddCheck(Check{
		Queries: []Rule{
			{
				Head: Predicate{Name: "caveat2", IDs: []Term{String("/a/file1")}},
				Body: []Predicate{
					{Name: "resource", IDs: []Term{String("/a/file1")}},
				},
			},
		},
	})
	require.NoError(t, err)

	biscuit3, err := biscuit2Deser.AppendBlock(rng, blockBuilder3)
	require.NoError(t, err)

	biscuit3Ser, err := biscuit3.Serialize()
	require.NoError(t, err)
	require.NotEmpty(t, biscuit3Ser)

	biscuit3Deser, err := Unmarshal(biscuit3Ser)
	require.NoError(t, err)

	authorizerBuilder3, err := biscuit3Deser.AuthorizerFor(WithSingularRootPublicKey(publicRoot))
	require.NoError(t, err)

	authorizerBuilder3.AddFact(
		Fact{Predicate: Predicate{Name: "resource", IDs: []Term{String("/a/file1")}}},
	)
	authorizerBuilder3.AddFact(
		Fact{Predicate: Predicate{Name: "operation", IDs: []Term{String("read")}}},
	)
	authorizerBuilder3.AddPolicy(DefaultAllowPolicy)

	authorizer3_1, err := authorizerBuilder3.Build()
	require.NoError(t, err)

	require.NoError(t, authorizer3_1.Authorize())

	authorizerBuilder3, err = biscuit3Deser.AuthorizerFor(WithSingularRootPublicKey(publicRoot))
	require.NoError(t, err)
	authorizerBuilder3.AddFact(
		Fact{Predicate: Predicate{Name: "resource", IDs: []Term{String("/a/file2")}}},
	)
	authorizerBuilder3.AddFact(
		Fact{Predicate: Predicate{Name: "operation", IDs: []Term{String("read")}}},
	)
	authorizerBuilder3.AddPolicy(DefaultAllowPolicy)

	authorizer3_2, err := authorizerBuilder3.Build()
	require.NoError(t, err)

	require.Error(t, authorizer3_2.Authorize())

	authorizerBuilder3, err = biscuit3Deser.AuthorizerFor(WithSingularRootPublicKey(publicRoot))
	require.NoError(t, err)
	authorizerBuilder3.AddFact(
		Fact{Predicate: Predicate{Name: "resource", IDs: []Term{String("/a/file1")}}},
	)
	authorizerBuilder3.AddFact(
		Fact{Predicate: Predicate{Name: "operation", IDs: []Term{String("write")}}},
	)
	authorizerBuilder3.AddPolicy(DefaultAllowPolicy)

	authorizer3_3, err := authorizerBuilder3.Build()
	require.NoError(t, err)

	require.Error(t, authorizer3_3.Authorize())

	// TODO this is helpful for basic compatibility testing, but should be replaced by using upstream sample test cases
	// from the eclipse-biscuit/biscuit repo.
	t.Run("inspect with biscuit cli", func(t *testing.T) {
		biscuitCLIPath, err := exec.LookPath("biscuit")
		require.NoError(t, err, "biscuit CLI not found in $PATH")

		dir := t.TempDir()

		biscuitFilepath := filepath.Join(dir, "biscuit.b64")
		err = os.WriteFile(biscuitFilepath, []byte(base64.URLEncoding.EncodeToString(biscuit3Ser)), 0o777)
		require.NoErrorf(t, err, "writing biscuit to file")

		pubKeyFilepath := filepath.Join(dir, "public_key")
		err = os.WriteFile(
			pubKeyFilepath,
			// `biscuit` CLI expects public key as hex, with a prefix specifying the alg
			[]byte(fmt.Sprintf(
				"ed25519/%s",
				hex.EncodeToString(publicRoot),
			)),
			0o777,
		)
		require.NoErrorf(t, err, "writing biscuit to file")

		var stdout, stderr bytes.Buffer
		cmd := exec.Command(biscuitCLIPath, "inspect", "--public-key-file", pubKeyFilepath, biscuitFilepath)
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err = cmd.Run()
		if err != nil {
			t.Log(stdout.String())
			t.Log(stderr.String())
			t.Fatalf("inspecting biscuit with CLI: %v", err)
		}
	})
}

func TestBiscuit_secp256r1(t *testing.T) {
	rng := rand.Reader
	const rootKeyID = 123
	const contextText = "current_context"
	privateRoot, err := ecdsa.GenerateKey(elliptic.P256(), rng)

	builder := NewBuilderSigner(
		privateRoot,
		WithRNG(rng),
		WithRootKeyID(rootKeyID))

	err = builder.AddAuthorityFact(Fact{
		Predicate: Predicate{Name: "right", IDs: []Term{String("/a/file1"), String("read")}},
	})
	require.NoError(t, err)
	err = builder.AddAuthorityFact(Fact{
		Predicate: Predicate{Name: "right", IDs: []Term{String("/a/file1"), String("write")}},
	})
	require.NoError(t, err)
	err = builder.AddAuthorityFact(Fact{
		Predicate: Predicate{Name: "right", IDs: []Term{String("/a/file2"), String("read")}},
	})
	require.NoError(t, err)

	builder.SetContext(contextText)

	b1, err := builder.Build()
	require.NoError(t, err)
	require.EqualValues(t, contextText, b1.GetContext(), "context authority")
	{
		keyID := b1.RootKeyID()
		require.NotNil(t, keyID, "root key ID present")
		require.EqualValues(t, rootKeyID, *keyID, "root key ID")
	}

	b1ser, err := b1.Serialize()
	require.NoError(t, err)
	require.NotEmpty(t, b1ser)

	b1deser, err := Unmarshal(b1ser)
	require.NoError(t, err)
	{
		keyID := b1deser.RootKeyID()
		require.NotNil(t, keyID, "root key ID present after round trip")
		require.EqualValues(t, rootKeyID, *keyID, "root key ID after round trip")
	}

	blockBuilder2 := b1deser.CreateBlock(2)
	err = blockBuilder2.AddCheck(Check{
		Queries: []Rule{
			{
				Head: Predicate{Name: "caveat", IDs: []Term{Variable("0")}},
				Body: []Predicate{
					{Name: "resource", IDs: []Term{Variable("0")}},
					{Name: "operation", IDs: []Term{String("read")}},
					{Name: "right", IDs: []Term{Variable("0"), String("read")}},
				},
			},
		},
	})
	require.NoError(t, err)

	b2, err := b1deser.AppendBlock(rng, blockBuilder2)
	require.NoError(t, err)

	b2ser, err := b2.Serialize()
	require.NoError(t, err)
	require.NotEmpty(t, b2ser)

	b2deser, err := Unmarshal(b2ser)
	require.NoError(t, err)

	blockBuilder3 := b2deser.CreateBlock(3)
	err = blockBuilder3.AddCheck(Check{
		Queries: []Rule{
			{
				Head: Predicate{Name: "caveat2", IDs: []Term{String("/a/file1")}},
				Body: []Predicate{
					{Name: "resource", IDs: []Term{String("/a/file1")}},
				},
			},
		},
	})
	require.NoError(t, err)

	b3, err := b2deser.AppendBlock(rng, blockBuilder3)
	require.NoError(t, err)

	b3ser, err := b3.Serialize()
	require.NoError(t, err)
	require.NotEmpty(t, b3ser)

	b3deser, err := Unmarshal(b3ser)
	require.NoError(t, err)

	vb3, err := b3deser.AuthorizerForCryptoPubKey(privateRoot.Public())
	require.NoError(t, err)

	vb3.AddFact(
		Fact{Predicate: Predicate{Name: "resource", IDs: []Term{String("/a/file1")}}},
	)
	vb3.AddFact(
		Fact{Predicate: Predicate{Name: "operation", IDs: []Term{String("read")}}},
	)
	vb3.AddPolicy(DefaultAllowPolicy)

	v3, err := vb3.Build()
	require.NoError(t, err)

	require.NoError(t, v3.Authorize())

	vb3, err = b3deser.AuthorizerForCryptoPubKey(privateRoot.Public())
	require.NoError(t, err)
	vb3.AddFact(
		Fact{Predicate: Predicate{Name: "resource", IDs: []Term{String("/a/file2")}}},
	)
	vb3.AddFact(
		Fact{Predicate: Predicate{Name: "operation", IDs: []Term{String("read")}}},
	)
	vb3.AddPolicy(DefaultAllowPolicy)

	v3, err = vb3.Build()
	require.NoError(t, err)

	require.Error(t, v3.Authorize())

	vb3, err = b3deser.AuthorizerForCryptoPubKey(privateRoot.Public())
	require.NoError(t, err)
	vb3.AddFact(
		Fact{Predicate: Predicate{Name: "resource", IDs: []Term{String("/a/file1")}}},
	)
	vb3.AddFact(
		Fact{Predicate: Predicate{Name: "operation", IDs: []Term{String("write")}}},
	)
	vb3.AddPolicy(DefaultAllowPolicy)

	v3, err = vb3.Build()
	require.NoError(t, err)

	require.Error(t, v3.Authorize())

	// TODO this is helpful for basic compatibility testing, but should be replaced by using upstream sample test cases
	// from the eclipse-biscuit/biscuit repo.
	t.Run("inspect with biscuit cli", func(t *testing.T) {
		biscuitCLIPath, err := exec.LookPath("biscuit")
		require.NoError(t, err, "biscuit CLI not found in $PATH")

		dir := t.TempDir()

		biscuitFilepath := filepath.Join(dir, "biscuit.b64")
		err = os.WriteFile(biscuitFilepath, []byte(base64.URLEncoding.EncodeToString(b3ser)), 0o777)
		require.NoErrorf(t, err, "writing biscuit to file")

		pubKeyFilepath := filepath.Join(dir, "public_key")
		err = os.WriteFile(
			pubKeyFilepath,
			// `biscuit` CLI expects public key as hex, with a prefix specifying the alg
			[]byte(fmt.Sprintf(
				"secp256r1/%s",
				hex.EncodeToString(
					elliptic.MarshalCompressed(elliptic.P256(), privateRoot.PublicKey.X, privateRoot.PublicKey.Y),
				),
			)),
			0o777,
		)
		require.NoErrorf(t, err, "writing biscuit to file")

		var stdout, stderr bytes.Buffer
		cmd := exec.Command(biscuitCLIPath, "inspect", "--public-key-file", pubKeyFilepath, biscuitFilepath)
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err = cmd.Run()
		if err != nil {
			t.Log(stdout.String())
			t.Log(stderr.String())
			t.Fatalf("inspecting biscuit with CLI: %v", err)
		}
	})
}

func TestSealedBiscuit(t *testing.T) {
	rng := rand.Reader
	publicRoot, privateRoot, _ := ed25519.GenerateKey(rng)

	builder := NewBuilder(privateRoot)

	err := builder.AddAuthorityFact(Fact{
		Predicate: Predicate{Name: "right", IDs: []Term{String("/a/file1"), String("read")}},
	})
	require.NoError(t, err)
	err = builder.AddAuthorityFact(Fact{
		Predicate: Predicate{Name: "right", IDs: []Term{String("/a/file1"), String("write")}},
	})
	require.NoError(t, err)
	err = builder.AddAuthorityFact(Fact{
		Predicate: Predicate{Name: "right", IDs: []Term{String("/a/file2"), String("read")}},
	})
	require.NoError(t, err)

	b1, err := builder.Build()
	require.NoError(t, err)

	b1ser, err := b1.Serialize()
	require.NoError(t, err)
	require.NotEmpty(t, b1ser)

	b1deser, err := Unmarshal(b1ser)
	require.NoError(t, err)

	blockBuilder2 := b1deser.CreateBlock(2)
	err = blockBuilder2.AddCheck(Check{
		Queries: []Rule{
			{
				Head: Predicate{Name: "caveat", IDs: []Term{Variable("0")}},
				Body: []Predicate{
					{Name: "resource", IDs: []Term{Variable("0")}},
					{Name: "operation", IDs: []Term{String("read")}},
					{Name: "right", IDs: []Term{Variable("0"), String("read")}},
				},
			},
		},
	})
	require.NoError(t, err)

	b2, err := b1deser.AppendBlock(rng, blockBuilder2)
	require.NoError(t, err)

	b2Seal, err := b2.Seal(rng)
	require.NoError(t, err)

	b2ser, err := b2Seal.Serialize()
	require.NoError(t, err)
	require.NotEmpty(t, b2ser)

	b2deser, err := Unmarshal(b2ser)
	require.NoError(t, err)

	_, err = b2deser.AuthorizerFor(WithSingularRootPublicKey(publicRoot))
	require.NoError(t, err)
}

func TestBiscuitRules(t *testing.T) {
	rng := rand.Reader
	publicRoot, privateRoot, _ := ed25519.GenerateKey(rng)

	builder := NewBuilder(privateRoot)

	err := builder.AddAuthorityRule(Rule{
		Head: Predicate{Name: "right", IDs: []Term{Variable("1"), String("read")}},
		Body: []Predicate{
			{Name: "resource", IDs: []Term{Variable("1")}},
			{Name: "owner", IDs: []Term{Variable("0"), Variable("1")}},
		},
	})
	require.NoError(t, err)
	err = builder.AddAuthorityRule(Rule{
		Head: Predicate{Name: "right", IDs: []Term{Variable("1"), String("write")}},
		Body: []Predicate{
			{Name: "resource", IDs: []Term{Variable("1")}},
			{Name: "owner", IDs: []Term{Variable("0"), Variable("1")}},
		},
	})
	require.NoError(t, err)
	err = builder.AddAuthorityCheck(Check{Queries: []Rule{
		{
			Head: Predicate{Name: "allowed_users", IDs: []Term{Variable("0")}},
			Body: []Predicate{
				{Name: "owner", IDs: []Term{Variable("0"), Variable("1")}},
			},
			Expressions: []Expression{
				{
					Value{NewSet(String("alice"), String("bob"))},
					Value{Variable("0")},
					BinaryContains,
				},
			},
		},
	}})
	require.NoError(t, err)

	b1, err := builder.Build()
	require.NoError(t, err)

	// b1 should allow alice & bob only
	// v, err := b1.Verify(publicRoot)
	// require.NoError(t, err)
	verifyOwner(t, *b1, publicRoot, map[string]bool{"alice": true, "bob": true, "eve": false})

	blockBuilder := b1.CreateBlock(1)
	err = blockBuilder.AddCheck(Check{
		Queries: []Rule{
			{
				Head: Predicate{Name: "caveat1", IDs: []Term{Variable("0"), Variable("1")}},
				Body: []Predicate{
					{Name: "right", IDs: []Term{Variable("0"), Variable("1")}},
					{Name: "resource", IDs: []Term{Variable("0")}},
					{Name: "operation", IDs: []Term{Variable("1")}},
				},
			},
		},
	})
	require.NoError(t, err)
	err = blockBuilder.AddCheck(Check{
		Queries: []Rule{
			{
				Head: Predicate{Name: "caveat2", IDs: []Term{Variable("0")}},
				Body: []Predicate{
					{Name: "resource", IDs: []Term{Variable("0")}},
					{Name: "owner", IDs: []Term{String("alice"), Variable("0")}},
				},
			},
		},
	})
	require.NoError(t, err)

	b2, err := b1.AppendBlock(rng, blockBuilder)
	require.NoError(t, err)

	// b2 should now only allow alice
	// v, err = b2.Verify(publicRoot)
	// require.NoError(t, err)
	verifyOwner(t, *b2, publicRoot, map[string]bool{"alice": true, "bob": false, "eve": false})
}

func verifyOwner(t *testing.T, b Biscuit, publicRoot ed25519.PublicKey, owners map[string]bool) {
	for user, valid := range owners {
		vb, err := b.AuthorizerFor(WithSingularRootPublicKey(publicRoot))
		require.NoError(t, err)

		t.Run(fmt.Sprintf("verify owner %s", user), func(t *testing.T) {
			vb.AddFact(
				Fact{Predicate: Predicate{Name: "resource", IDs: []Term{String("file1")}}},
			)
			vb.AddFact(
				Fact{Predicate: Predicate{Name: "operation", IDs: []Term{String("write")}}},
			)
			vb.AddFact(
				Fact{
					Predicate: Predicate{
						Name: "owner",
						IDs: []Term{
							String(user),
							String("file1"),
						},
					},
				},
			)
			vb.AddPolicy(DefaultAllowPolicy)

			v, err := vb.Build()
			require.NoError(t, err)

			if valid {
				require.NoError(t, v.Authorize())
			} else {
				require.Error(t, v.Authorize())
			}
		})
	}
}

func TestCheckRootKey(t *testing.T) {
	rng := rand.Reader
	const rootKeyID = 123
	publicRoot, privateRoot, _ := ed25519.GenerateKey(rng)

	builder := NewBuilder(privateRoot, WithRootKeyID(rootKeyID))

	b, err := builder.Build()
	require.NoError(t, err)

	_, err = b.AuthorizerFor(WithRootPublicKeys(map[uint32]ed25519.PublicKey{
		rootKeyID: publicRoot,
	}, nil))
	require.NoError(t, err)

	_, err = b.AuthorizerFor(WithRootPublicKeys(map[uint32]ed25519.PublicKey{
		rootKeyID + 1: publicRoot,
	}, nil))
	require.ErrorIs(t, err, ErrNoPublicKeyAvailable)

	_, err = b.AuthorizerFor(WithRootPublicKeys(map[uint32]ed25519.PublicKey{
		rootKeyID: nil,
	}, nil))
	require.ErrorIs(t, err, ErrNoPublicKeyAvailable)

	publicNotRoot, _, _ := ed25519.GenerateKey(rng)
	_, err = b.AuthorizerFor(WithSingularRootPublicKey(publicNotRoot))
	require.Equal(t, ErrInvalidSignature, err)
}

func TestGenerateWorld(t *testing.T) {
	rng := rand.Reader
	_, privateRoot, _ := ed25519.GenerateKey(rng)

	biscuitBuilder0 := NewBuilder(privateRoot)

	authorityFact1 := Fact{Predicate: Predicate{Name: "fact1", IDs: []Term{String("file1")}}}
	authorityFact2 := Fact{Predicate: Predicate{Name: "fact2", IDs: []Term{String("file2")}}}

	authorityRule1 := Rule{
		Head: Predicate{Name: "right", IDs: []Term{Variable("1"), String("read")}},
		Body: []Predicate{
			{Name: "resource", IDs: []Term{Variable("1")}},
			{Name: "owner", IDs: []Term{Variable("0"), Variable("1")}},
		},
	}
	authorityRule2 := Rule{
		Head: Predicate{Name: "right", IDs: []Term{Variable("1"), String("write")}},
		Body: []Predicate{
			{Name: "resource", IDs: []Term{Variable("1")}},
			{Name: "owner", IDs: []Term{Variable("0"), Variable("1")}},
		},
	}

	err := biscuitBuilder0.AddAuthorityFact(authorityFact1)
	require.NoError(t, err)
	err = biscuitBuilder0.AddAuthorityFact(authorityFact2)
	require.NoError(t, err)
	err = biscuitBuilder0.AddAuthorityRule(authorityRule1)
	require.NoError(t, err)
	err = biscuitBuilder0.AddAuthorityRule(authorityRule2)
	require.NoError(t, err)

	b, err := biscuitBuilder0.Build()
	require.NoError(t, err)

	symbolTable := b.symbols
	publicKeys := datalog.NewPublicKeyTable()
	world, err := b.generateWorld(defaultSymbolTable.Clone())
	require.NoError(t, err)

	require.Equal(t, uint64(2), world.Facts.Count())
	{
		f1 := authorityFact1.convert(symbolTable)
		f2 := authorityFact2.convert(symbolTable)
		require.Equal(t,
			set.Sorted(world.Facts.AllFacts()),
			set.Sorted(set.NewHashSet(f1, f2).Iter()),
		)
	}
	require.Equal(t, uint64(2), world.Rules.Count())
	{
		r1 := authorityRule1.Convert(symbolTable, publicKeys)
		r2 := authorityRule2.Convert(symbolTable, publicKeys)
		require.Equal(t,
			set.Sorted(world.Rules.AllRules()),
			set.Sorted(set.NewHashSet(r1, r2).Iter()),
		)
	}

	blockBuilder1 := b.CreateBlock(1)
	blockRule := Rule{
		Head: Predicate{Name: "blockRule", IDs: []Term{Variable("1")}},
		Body: []Predicate{
			{Name: "resource", IDs: []Term{Variable("1")}},
			{Name: "owner", IDs: []Term{String("alice"), Variable("1")}},
		},
	}
	err = blockBuilder1.AddRule(blockRule)
	require.NoError(t, err)

	blockFact := Fact{Predicate{Name: "resource", IDs: []Term{String("file1")}}}
	err = blockBuilder1.AddFact(blockFact)
	require.NoError(t, err)

	biscuit2, err := b.AppendBlock(rng, blockBuilder1)
	require.NoError(t, err)

	symbolTable2 := append(*symbolTable, *biscuit2.blocks[len(biscuit2.blocks)-1].symbols...)
	publicKeys2 := append(*publicKeys, *biscuit2.blocks[len(biscuit2.blocks)-1].publicKeys...)
	world, err = biscuit2.generateWorld(&symbolTable2)
	require.NoError(t, err)

	require.Equal(t, uint64(3), world.Facts.Count())
	{
		f1 := blockFact.convert(&symbolTable2)
		f2 := authorityFact1.convert(&symbolTable2)
		f3 := authorityFact2.convert(&symbolTable2)
		require.Equal(t,
			set.Sorted(world.Facts.AllFacts()),
			set.Sorted(set.NewHashSet(f1, f2, f3).Iter()),
		)
	}
	require.Equal(t, uint64(3), world.Rules.Count())
	{
		r1 := authorityRule1.Convert(&symbolTable2, &publicKeys2)
		r2 := authorityRule2.Convert(&symbolTable2, &publicKeys2)
		r3 := blockRule.Convert(&symbolTable2, &publicKeys2)
		require.Equal(t,
			set.Sorted(world.Rules.AllRules()),
			set.Sorted(set.NewHashSet(r1, r2, r3).Iter()),
		)
	}
}

func TestAppendErrors(t *testing.T) {
	rng := rand.Reader
	_, privateRoot, _ := ed25519.GenerateKey(rng)
	builder := NewBuilder(privateRoot)
	newFact := Fact{
		Predicate: Predicate{Name: "newfact", IDs: []Term{String("/a/file1"), String("read")}},
	}
	err := builder.AddAuthorityFact(newFact)
	require.NoError(t, err)

	t.Run("Strings overlap", func(t *testing.T) {
		b, err := builder.Build()
		require.NoError(t, err)

		bb := NewBlockBuilder(WithSymbolStart(0))
		err = bb.AddFact(newFact)
		require.NoError(t, err)

		_, err = b.AppendBlock(rng, bb)
		require.Equal(t, ErrSymbolTableOverlap, err)
	})

	t.Run("biscuit is sealed", func(t *testing.T) {
		b, err := builder.Build()
		require.NoError(t, err)

		bb1 := NewBlockBuilder()
		bb1.SetBlockID(1)
		err = bb1.AddFact(Fact{
			Predicate: Predicate{Name: "test_fact", IDs: []Term{String("value")}},
		})
		require.NoError(t, err)

		b2, err := b.AppendBlock(rng, bb1)
		require.NoError(t, err)

		// Seal the biscuit
		sealed, err := b2.Seal(rng)
		require.NoError(t, err)

		// Try appending to the sealed biscuit
		bb2 := NewBlockBuilder()
		err = bb2.AddFact(Fact{
			Predicate: Predicate{Name: "another_fact", IDs: []Term{String("value2")}},
		})
		require.NoError(t, err)

		_, err = sealed.AppendBlock(rng, bb2)
		require.Error(t, err)
		require.ErrorContains(t, err, "token is sealed")
	})
}

func TestNewErrors(t *testing.T) {
	rng := rand.Reader

	t.Run("authority block Strings overlap", func(t *testing.T) {
		_, privateRoot, _ := ed25519.GenerateKey(rng)
		_, err := New(rng, privateRoot, datalog.SymbolTable{"String1", "String2"}, &Block{
			symbols: &datalog.SymbolTable{"String1"},
		})
		require.Equal(t, ErrSymbolTableOverlap, err)
	})
}

func TestBiscuitVerifyErrors(t *testing.T) {
	rng := rand.Reader
	publicRoot, privateRoot, _ := ed25519.GenerateKey(rng)

	builder := NewBuilder(privateRoot)
	b, err := builder.Build()
	require.NoError(t, err)

	_, err = b.AuthorizerFor(WithSingularRootPublicKey(publicRoot))
	require.NoError(t, err)

	publicTest, _, _ := ed25519.GenerateKey(rng)
	_, err = b.AuthorizerFor(WithSingularRootPublicKey(publicTest))
	require.Error(t, err)
}

/*FIXME
func TestBiscuitSha256Sum(t *testing.T) {
	rng := rand.Reader
	publicRoot, privateRoot, err := ed25519.GenerateKey(rng)

	builder := NewBuilder(privateRoot)
	b, err := builder.Build()
	require.NoError(t, err)

	require.Equal(t, 0, b.BlockCount())
	h0, err := b.SHA256Sum(0)
	require.NoError(t, err)
	require.NotEmpty(t, h0)

	_, err = b.SHA256Sum(1)
	require.Error(t, err)
	_, err = b.SHA256Sum(-1)
	require.Error(t, err)

	blockBuilder := b.SignRequest()
	b, err = b.Append(rng, root, blockBuilder.Build())
	require.NoError(t, err)
	require.Equal(t, 1, b.BlockCount())
p
	h10, err := b.SHA256Sum(0)
	require.NoError(t, err)
	require.Equal(t, h0, h10)
	h11, err := b.SHA256Sum(1)
	require.NoError(t, err)
	require.NotEmpty(t, h11)

	blockBuilder = b.SignRequest()
	b, err = b.Append(rng, root, blockBuilder.Build())
	require.NoError(t, err)
	require.Equal(t, 2, b.BlockCount())

	h20, err := b.SHA256Sum(0)
	require.NoError(t, err)
	require.Equal(t, h0, h20)
	h21, err := b.SHA256Sum(1)
	require.NoError(t, err)
	require.Equal(t, h11, h21)
	h22, err := b.SHA256Sum(2)
	require.NoError(t, err)
	require.NotEmpty(t, h22)
}
*/

func TestGetBlockID(t *testing.T) {
	rng := rand.Reader
	_, privateRoot, _ := ed25519.GenerateKey(rng)
	builder := NewBuilder(privateRoot)

	// add 3 facts authority_0_fact_{0,1,2} in authority block
	for i := 0; i < 3; i++ {
		require.NoError(t, builder.AddAuthorityFact(Fact{Predicate: Predicate{
			Name: fmt.Sprintf("authority_0_fact_%d", i),
			IDs:  []Term{Integer(i)},
		}}))
	}

	b, err := builder.Build()
	require.NoError(t, err)

	// add 2 extra signedBlocks each containing 3 facts block_{0,1}_fact_{0,1,2}
	for i := range 2 {
		blockID := uint64(i + 1)
		blockBuilder := b.CreateBlock(blockID)
		for j := range 3 {
			err := blockBuilder.AddFact(
				Fact{Predicate: Predicate{
					Name: fmt.Sprintf("block_%d_fact_%d", i, j),
					IDs:  []Term{String("block"), Integer(i), Integer(j)},
				}},
			)
			require.NoError(t, err)
		}
		b, err = b.AppendBlock(rng, blockBuilder)
		require.NoError(t, err)
	}

	idx, err := b.GetBlockID(Fact{Predicate{
		Name: "authority_0_fact_0",
		IDs:  []Term{Integer(0)},
	}})
	require.NoError(t, err)
	require.Equal(t, 0, idx)
	idx, err = b.GetBlockID(Fact{Predicate{
		Name: "authority_0_fact_2",
		IDs:  []Term{Integer(2)},
	}})
	require.NoError(t, err)
	require.Equal(t, 0, idx)

	idx, err = b.GetBlockID(Fact{Predicate{
		Name: "block_0_fact_2",
		IDs:  []Term{String("block"), Integer(0), Integer(2)},
	}})
	require.NoError(t, err)
	require.Equal(t, 1, idx)
	idx, err = b.GetBlockID(Fact{Predicate{
		Name: "block_1_fact_1",
		IDs:  []Term{String("block"), Integer(1), Integer(1)},
	}})
	require.NoError(t, err)
	require.Equal(t, 2, idx)

	_, err = b.GetBlockID(Fact{Predicate{
		Name: "block_1_fact_3",
		IDs:  []Term{String("block"), Integer(1), Integer(3)},
	}})
	require.Equal(t, ErrFactNotFound, err)
	_, err = b.GetBlockID(Fact{Predicate{
		Name: "block_2_fact_1",
		IDs:  []Term{String("block"), Integer(2), Integer(1)},
	}})
	require.Equal(t, ErrFactNotFound, err)
	_, err = b.GetBlockID(Fact{Predicate{
		Name: "block_1_fact_1",
		IDs:  []Term{Integer(1), Integer(1)},
	}})
	require.Equal(t, ErrFactNotFound, err)
}

func TestInvalidRuleGeneration(t *testing.T) {
	rng := rand.Reader
	publicRoot, privateRoot, _ := ed25519.GenerateKey(rng)
	builder := NewBuilder(privateRoot)
	err := builder.AddAuthorityCheck(Check{Queries: []Rule{
		{
			Head: Predicate{Name: "check1"},
			Body: []Predicate{
				{Name: "operation", IDs: []Term{String("read")}},
			},
		},
	}})
	require.NoError(t, err)

	b, err := builder.Build()
	require.NoError(t, err)
	t.Log(b.String())

	blockBuilder := b.CreateBlock(1)
	err = blockBuilder.AddRule(
		Rule{
			Head: Predicate{Name: "operation", IDs: []Term{Variable("sym"), String("read")}},
			Body: []Predicate{
				{Name: "operation", IDs: []Term{Variable("sym"), Variable("operation")}},
			},
		},
	)
	require.NoError(t, err)

	b, err = b.AppendBlock(rng, blockBuilder)
	require.NoError(t, err)
	t.Log(b.String())

	authorizerBuilder, err := b.AuthorizerFor(WithSingularRootPublicKey(publicRoot))
	require.NoError(t, err)

	authorizerBuilder.AddFact(
		Fact{Predicate: Predicate{
			Name: "operation",
			IDs:  []Term{String("write")},
		}},
	)

	authorizer, err := authorizerBuilder.Build()
	require.NoError(t, err)

	err = authorizer.Authorize()
	t.Log(authorizer.PrintWorld())
	require.Error(t, err)
}
