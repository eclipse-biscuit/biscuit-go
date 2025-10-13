// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package biscuit

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/eclipse-biscuit/biscuit-go/v2/datalog"
	"github.com/stretchr/testify/require"
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

	builder.AddAuthorityFact(Fact{
		Predicate: Predicate{Name: "right", IDs: []Term{String("/a/file1"), String("read")}},
	})
	builder.AddAuthorityFact(Fact{
		Predicate: Predicate{Name: "right", IDs: []Term{String("/a/file1"), String("write")}},
	})
	builder.AddAuthorityFact(Fact{
		Predicate: Predicate{Name: "right", IDs: []Term{String("/a/file2"), String("read")}},
	})

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

	block2 := b1deser.CreateBlock()
	block2.AddCheck(Check{
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

	b2, err := b1deser.Append(rng, block2.Build())
	require.NoError(t, err)

	b2ser, err := b2.Serialize()
	require.NoError(t, err)
	require.NotEmpty(t, b2ser)

	b2deser, err := Unmarshal(b2ser)
	require.NoError(t, err)

	block3 := b2deser.CreateBlock()
	block3.AddCheck(Check{
		Queries: []Rule{
			{
				Head: Predicate{Name: "caveat2", IDs: []Term{String("/a/file1")}},
				Body: []Predicate{
					{Name: "resource", IDs: []Term{String("/a/file1")}},
				},
			},
		},
	})

	b3, err := b2deser.Append(rng, block3.Build())
	require.NoError(t, err)

	b3ser, err := b3.Serialize()
	require.NoError(t, err)
	require.NotEmpty(t, b3ser)

	b3deser, err := Unmarshal(b3ser)
	require.NoError(t, err)

	v3, err := b3deser.AuthorizerFor(WithSingularRootPublicKey(publicRoot))
	require.NoError(t, err)

	v3.AddFact(Fact{Predicate: Predicate{Name: "resource", IDs: []Term{String("/a/file1")}}})
	v3.AddFact(Fact{Predicate: Predicate{Name: "operation", IDs: []Term{String("read")}}})
	v3.AddPolicy(DefaultAllowPolicy)
	require.NoError(t, v3.Authorize())

	v3, err = b3deser.AuthorizerFor(WithSingularRootPublicKey(publicRoot))
	require.NoError(t, err)
	v3.AddFact(Fact{Predicate: Predicate{Name: "resource", IDs: []Term{String("/a/file2")}}})
	v3.AddFact(Fact{Predicate: Predicate{Name: "operation", IDs: []Term{String("read")}}})
	v3.AddPolicy(DefaultAllowPolicy)
	require.Error(t, v3.Authorize())

	v3, err = b3deser.AuthorizerFor(WithSingularRootPublicKey(publicRoot))
	require.NoError(t, err)
	v3.AddFact(Fact{Predicate: Predicate{Name: "resource", IDs: []Term{String("/a/file1")}}})
	v3.AddFact(Fact{Predicate: Predicate{Name: "operation", IDs: []Term{String("write")}}})
	v3.AddPolicy(DefaultAllowPolicy)
	require.Error(t, v3.Authorize())
}

func TestSealedBiscuit(t *testing.T) {
	rng := rand.Reader
	publicRoot, privateRoot, _ := ed25519.GenerateKey(rng)

	builder := NewBuilder(privateRoot)

	builder.AddAuthorityFact(Fact{
		Predicate: Predicate{Name: "right", IDs: []Term{String("/a/file1"), String("read")}},
	})
	builder.AddAuthorityFact(Fact{
		Predicate: Predicate{Name: "right", IDs: []Term{String("/a/file1"), String("write")}},
	})
	builder.AddAuthorityFact(Fact{
		Predicate: Predicate{Name: "right", IDs: []Term{String("/a/file2"), String("read")}},
	})

	b1, err := builder.Build()
	require.NoError(t, err)

	b1ser, err := b1.Serialize()
	require.NoError(t, err)
	require.NotEmpty(t, b1ser)

	b1deser, err := Unmarshal(b1ser)
	require.NoError(t, err)

	block2 := b1deser.CreateBlock()
	block2.AddCheck(Check{
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

	b2, err := b1deser.Append(rng, block2.Build())
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

	builder.AddAuthorityRule(Rule{
		Head: Predicate{Name: "right", IDs: []Term{Variable("1"), String("read")}},
		Body: []Predicate{
			{Name: "resource", IDs: []Term{Variable("1")}},
			{Name: "owner", IDs: []Term{Variable("0"), Variable("1")}},
		},
	})
	builder.AddAuthorityRule(Rule{
		Head: Predicate{Name: "right", IDs: []Term{Variable("1"), String("write")}},
		Body: []Predicate{
			{Name: "resource", IDs: []Term{Variable("1")}},
			{Name: "owner", IDs: []Term{Variable("0"), Variable("1")}},
		},
	})
	builder.AddAuthorityCheck(Check{Queries: []Rule{
		{
			Head: Predicate{Name: "allowed_users", IDs: []Term{Variable("0")}},
			Body: []Predicate{
				{Name: "owner", IDs: []Term{Variable("0"), Variable("1")}},
			},
			Expressions: []Expression{
				{
					Value{Set{String("alice"), String("bob")}},
					Value{Variable("0")},
					BinaryContains,
				},
			},
		},
	}})

	b1, err := builder.Build()
	require.NoError(t, err)

	// b1 should allow alice & bob only
	// v, err := b1.Verify(publicRoot)
	// require.NoError(t, err)
	verifyOwner(t, *b1, publicRoot, map[string]bool{"alice": true, "bob": true, "eve": false})

	block := b1.CreateBlock()
	block.AddCheck(Check{
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
	block.AddCheck(Check{
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

	b2, err := b1.Append(rng, block.Build())
	require.NoError(t, err)

	// b2 should now only allow alice
	// v, err = b2.Verify(publicRoot)
	// require.NoError(t, err)
	verifyOwner(t, *b2, publicRoot, map[string]bool{"alice": true, "bob": false, "eve": false})
}

func verifyOwner(t *testing.T, b Biscuit, publicRoot ed25519.PublicKey, owners map[string]bool) {
	for user, valid := range owners {
		v, err := b.AuthorizerFor(WithSingularRootPublicKey(publicRoot))
		require.NoError(t, err)

		t.Run(fmt.Sprintf("verify owner %s", user), func(t *testing.T) {
			v.AddFact(Fact{Predicate: Predicate{Name: "resource", IDs: []Term{String("file1")}}})
			v.AddFact(Fact{Predicate: Predicate{Name: "operation", IDs: []Term{String("write")}}})
			v.AddFact(Fact{
				Predicate: Predicate{
					Name: "owner",
					IDs: []Term{
						String(user),
						String("file1"),
					},
				},
			})
			v.AddPolicy(DefaultAllowPolicy)

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

	build := NewBuilder(privateRoot)

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

	build.AddAuthorityFact(authorityFact1)
	build.AddAuthorityFact(authorityFact2)
	build.AddAuthorityRule(authorityRule1)
	build.AddAuthorityRule(authorityRule2)

	b, err := build.Build()
	require.NoError(t, err)

	StringTable := (build.(*builderOptions)).symbols
	world, err := b.generateWorld(defaultSymbolTable.Clone())
	require.NoError(t, err)

	expectedWorld := datalog.NewWorld()
	expectedWorld.AddFact(authorityFact1.convert(StringTable))
	expectedWorld.AddFact(authorityFact2.convert(StringTable))
	expectedWorld.AddRule(authorityRule1.convert(StringTable))
	expectedWorld.AddRule(authorityRule2.convert(StringTable))
	require.Equal(t, expectedWorld, world)

	blockBuild := b.CreateBlock()
	blockRule := Rule{
		Head: Predicate{Name: "blockRule", IDs: []Term{Variable("1")}},
		Body: []Predicate{
			{Name: "resource", IDs: []Term{Variable("1")}},
			{Name: "owner", IDs: []Term{String("alice"), Variable("1")}},
		},
	}
	blockBuild.AddRule(blockRule)

	blockFact := Fact{Predicate{Name: "resource", IDs: []Term{String("file1")}}}
	blockBuild.AddFact(blockFact)

	b2, err := b.Append(rng, blockBuild.Build())
	require.NoError(t, err)

	allStrings := append(*StringTable, *(blockBuild.(*blockBuilder)).symbols...)
	world, err = b2.generateWorld(&allStrings)
	require.NoError(t, err)

	expectedWorld = datalog.NewWorld()
	expectedWorld.AddFact(authorityFact1.convert(&allStrings))
	expectedWorld.AddFact(authorityFact2.convert(&allStrings))
	expectedWorld.AddFact(blockFact.convert(&allStrings))
	expectedWorld.AddRule(authorityRule1.convert(&allStrings))
	expectedWorld.AddRule(authorityRule2.convert(&allStrings))
	expectedWorld.AddRule(
		blockRule.convert(&allStrings),
	)
	require.Equal(t, expectedWorld, world)
}

func TestAppendErrors(t *testing.T) {
	rng := rand.Reader
	_, privateRoot, _ := ed25519.GenerateKey(rng)
	builder := NewBuilder(privateRoot)
	builder.AddAuthorityFact(Fact{
		Predicate: Predicate{Name: "newfact", IDs: []Term{String("/a/file1"), String("read")}},
	})

	t.Run("Strings overlap", func(t *testing.T) {
		b, err := builder.Build()
		require.NoError(t, err)

		_, err = b.Append(rng, &Block{
			symbols: &datalog.SymbolTable{"newfact"},
		})
		require.Equal(t, ErrSymbolTableOverlap, err)
	})

	t.Run("biscuit is sealed", func(t *testing.T) {
		b, err := builder.Build()
		require.NoError(t, err)

		_, err = b.Append(rng, &Block{
			symbols: &datalog.SymbolTable{},
			facts:   &datalog.FactSet{},
		})
		require.NoError(t, err)

		b.container = nil
		_, err = b.Append(rng, &Block{
			symbols: &datalog.SymbolTable{},
		})
		require.Error(t, err)
	})
}

func TestNewErrors(t *testing.T) {
	rng := rand.Reader

	t.Run("authority block Strings overlap", func(t *testing.T) {
		_, privateRoot, _ := ed25519.GenerateKey(rng)
		_, err := New(rng, privateRoot, &datalog.SymbolTable{"String1", "String2"}, &Block{
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

	blockBuilder := b.CreateBlock()
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

	blockBuilder = b.CreateBlock()
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
	// add 2 extra blocks each containing 3 facts block_{0,1}_fact_{0,1,2}
	for i := 0; i < 2; i++ {
		blockBuilder := b.CreateBlock()
		for j := 0; j < 3; j++ {
			blockBuilder.AddFact(Fact{Predicate: Predicate{
				Name: fmt.Sprintf("block_%d_fact_%d", i, j),
				IDs:  []Term{String("block"), Integer(i), Integer(j)},
			}})
		}
		b, err = b.Append(rng, blockBuilder.Build())
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
	builder.AddAuthorityCheck(Check{Queries: []Rule{
		{
			Head: Predicate{Name: "check1"},
			Body: []Predicate{
				{Name: "operation", IDs: []Term{String("read")}},
			},
		},
	}})

	b, err := builder.Build()
	require.NoError(t, err)
	t.Log(b.String())

	blockBuilder := b.CreateBlock()
	blockBuilder.AddRule(Rule{
		Head: Predicate{Name: "operation", IDs: []Term{Variable("sym"), String("read")}},
		Body: []Predicate{
			{Name: "operation", IDs: []Term{Variable("sym"), Variable("operation")}},
		},
	})

	block := blockBuilder.Build()
	b, err = b.Append(rng, block)
	require.NoError(t, err)
	t.Log(b.String())

	verifier, err := b.AuthorizerFor(WithSingularRootPublicKey(publicRoot))
	require.NoError(t, err)

	verifier.AddFact(Fact{Predicate: Predicate{
		Name: "operation",
		IDs:  []Term{String("write")},
	}})

	err = verifier.Authorize()
	t.Log(verifier.PrintWorld())
	require.Error(t, err)
}
