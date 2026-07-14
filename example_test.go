package biscuit_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/eclipse-biscuit/biscuit-go/v2/parser"
)

func TestBiscuit_RoundTrip(t *testing.T) {
	// Generate a root key.
	rng := rand.Reader
	publicRoot, privateRoot, _ := ed25519.GenerateKey(rng)

	// Build an authority block with some basic rights as facts.
	authority, err := parser.FromStringBlockWithParams(`
		right("/a/file1.txt", {read});
		right("/a/file1.txt", {write});
		right("/a/file2.txt", {read});
		right("/a/file3.txt", {write});
	`, map[string]biscuit.Term{"read": biscuit.String("read"), "write": biscuit.String("write")})
	require.NoError(t, err, "failed to parse authority block")

	builder := biscuit.NewBuilder(privateRoot)
	err = builder.AddBlock(authority)
	require.NoError(t, err, "failed to add block")

	b, err := builder.Build()
	require.NoError(t, err, "failed to build block")

	// Serialize this biscuit with just an authority block.
	token, err := b.Serialize()
	require.NoError(t, err, "failed to serialize biscuit")

	t.Logf("Token1 length: %d\n", len(token))

	// Deserialize this biscuit with just an authority block.
	deser, err := biscuit.Unmarshal(token)
	require.NoError(t, err, "failed to deserialize biscuit")

	// Add some attenuation by appending a block with a check if statement.
	blockBuilder := deser.CreateBlock(0)

	block, err := parser.FromStringBlockWithParams(`
			check if resource($file), operation($permission), {{read}}.contains($permission);`,
		map[string]biscuit.Term{"read": biscuit.String("read")})
	require.NoError(t, err, "failed to parse block")

	err = blockBuilder.AddBlock(block)
	require.NoError(t, err, "failed to add block")

	b2, err := deser.AppendBlock(rng, blockBuilder)
	require.NoError(t, err, "failed to append block")

	// Serialize this biscuit with an authority block and one appended block.
	token2, err := b2.Serialize()
	require.NoError(t, err, "failed to serialize biscuit")

	t.Logf("Token2 length: %d\n", len(token2))

	// Verify and authorize the attenuated biscuit.
	// First check that biscuit b2 is authorized to read the file `/a/file1.txt`.
	b2, err = biscuit.Unmarshal(token2)
	require.NoError(t, err, "failed to deserialize biscuit")

	vb1, err := b2.Authorizer(publicRoot)
	require.NoError(t, err)

	authorizer, err := parser.FromStringAuthorizerWithParams(`
		resource({res});
		operation({op});
		allow if right({res}, {op});
		`, map[string]biscuit.Term{"res": biscuit.String("/a/file1.txt"), "op": biscuit.String("read")})
	require.NoError(t, err, "failed to parse authorizer")
	vb1.AddAuthorizer(authorizer)

	v1, err := vb1.Build()
	require.NoError(t, err)

	err = v1.Authorize()
	assert.NoError(t, err)

	// Second, check that biscuit b2 is *not* authorized to write the file `/a/file2.txt` (because of the attenuation).
	vb1, err = b2.Authorizer(publicRoot)
	require.NoError(t, err)

	authorizer, err = parser.FromStringAuthorizerWithParams(`
		resource({res});
		operation({op});
		allow if right({res}, {op});
		`, map[string]biscuit.Term{"res": biscuit.String("/a/file1.txt"), "op": biscuit.String("write")})
	require.NoError(t, err, "failed to parse authorizer")

	vb1.AddAuthorizer(authorizer)

	v1, err = vb1.Build()
	require.NoError(t, err)

	err = v1.Authorize()
	require.Error(t, err)
}
