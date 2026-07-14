package crypto_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	biscuitcrypto "github.com/eclipse-biscuit/biscuit-go/v2/internal/crypto"
	"github.com/stretchr/testify/require"
)

func TestNewSigVerifier(t *testing.T) {
	ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ecdsaPublicKey, ok := ecdsaPrivateKey.Public().(*ecdsa.PublicKey)
	require.True(t, ok)

	ed25519PublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	testCases := map[string]struct {
		given       crypto.PublicKey
		expectError error
	}{
		"ed25519 public key": {
			given:       ed25519PublicKey,
			expectError: nil,
		},
		"ecdsa public key": {
			given:       ecdsaPublicKey,
			expectError: nil,
		},
		"string": {
			given:       "some-string",
			expectError: errors.New("biscuit: unsupported public key type string"),
		},
	}
	for name, tt := range testCases {
		t.Run(name, func(t *testing.T) {
			_, err := biscuitcrypto.NewSigVerifier(tt.given)
			if tt.expectError == nil {
				require.NoError(t, err)
				return
			}

			require.ErrorContains(t, err, tt.expectError.Error())
		})
	}
}
