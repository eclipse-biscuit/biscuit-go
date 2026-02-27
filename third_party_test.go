package biscuit_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/eclipse-biscuit/biscuit-go/v2/parser"
)

func TestThirdPartySignatureVerification(t *testing.T) {
	rng := rand.Reader
	publicRoot, privateRoot, err := ed25519.GenerateKey(rng)
	require.NoError(t, err)

	builder := biscuit.NewBuilder(privateRoot)

	token, err := builder.Build()
	require.NoError(t, err)

	blockBuilder := token.CreateBlock(1)
	err = blockBuilder.AddFact(
		biscuit.Fact{
			Predicate: biscuit.Predicate{
				Name: "user",
				IDs:  []biscuit.Term{biscuit.String("somebody")},
			},
		},
	)
	require.NoError(t, err)

	token, err = token.AppendBlock(rng, blockBuilder)
	require.NoError(t, err)

	// Generate a third party request
	thirdPartyRequest, err := token.ThirdPartyBlockRequest()
	require.NoError(t, err)

	// Serialize and deserialize the third party request.
	thirdPartyRequestBytes, err := thirdPartyRequest.Serialize()
	require.NoError(t, err)

	thirdPartyRequestDeser, err := biscuit.UnmarshalThirdPartyBlockRequest(thirdPartyRequestBytes)
	require.NoError(t, err)

	// Create the block contents over a single fact.
	blockBuilder2 := biscuit.NewBlockBuilder()
	externalFact, err := parser.FromStringFact(`external_fact("1234")`)
	require.NoError(t, err)
	err = blockBuilder2.AddFact(externalFact)
	require.NoError(t, err)

	// Have the third party sign the request over these block contents.
	_, externalSigner, err := ed25519.GenerateKey(rng)
	require.NoError(t, err)

	thirdPartyBlockContents, err := thirdPartyRequestDeser.SignRequest(externalSigner, blockBuilder2)
	require.NoError(t, err)

	thirdPartyBlockContentsBytes, err := thirdPartyBlockContents.Serialize()
	require.NoError(t, err)

	thirdPartyBlockContentsDeser, err := biscuit.UnmarshalThirdPartyBlockContents(thirdPartyBlockContentsBytes)
	require.NoError(t, err)

	tokenWithTPB, err := token.AppendThirdPartyBlock(rng, thirdPartyBlockContentsDeser)
	require.NoError(t, err)

	authorizerBuilder, err := tokenWithTPB.Authorizer(publicRoot)
	require.NoError(t, err)

	authorizerBuilder.AddPolicy(biscuit.DefaultAllowPolicy)

	authorizer, err := authorizerBuilder.Build()
	require.NoError(t, err)

	err = authorizer.Authorize()
	require.NoError(t, err)
}
