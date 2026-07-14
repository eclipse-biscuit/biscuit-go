package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/eclipse-biscuit/biscuit-go/v2/pb"
)

type SECP256R1Signer struct {
	private *ecdsa.PrivateKey
}

func (s SECP256R1Signer) Sign(payload []byte) ([]byte, error) {
	digest := sha256.Sum256(payload)
	return ecdsa.SignASN1(rand.Reader, s.private, digest[:])
}

func (s SECP256R1Signer) Algorithm() pb.PublicKey_Algorithm {
	return pb.PublicKey_SECP256R1
}

func (s SECP256R1Signer) PublicKeyProto() (*pb.PublicKey, error) {
	public := elliptic.MarshalCompressed(elliptic.P256(), s.private.PublicKey.X, s.private.PublicKey.Y)
	return &pb.PublicKey{
		Algorithm: pb.PublicKey_SECP256R1.Enum(),
		Key:       public,
	}, nil
}

func (s *SECP256R1Signer) UnmarshalBinary(data []byte) error {
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), data)
	if err != nil {
		return fmt.Errorf("failed to parse the private key: %w", err)
	}

	*s = SECP256R1Signer{
		private: priv,
	}

	return nil
}

type SECP256R1Generator struct{}

func (s SECP256R1Generator) GenerateNext(rng io.Reader) ([]byte, []byte, error) {
	p256 := elliptic.P256()

	priv, err := ecdsa.GenerateKey(p256, rng)
	if err != nil {
		return nil, nil, err
	}

	// https://github.com/eclipse-biscuit/biscuit/blob/main/SPECIFICATIONS.md#ecdsa
	// The private key must be exactly 32 bytes (256 bits) for secp256r1, so we need to pad it to the correct length.
	rawPriv := make([]byte, 32)
	priv.D.FillBytes(rawPriv)
	rawPub := elliptic.MarshalCompressed(p256, priv.PublicKey.X, priv.PublicKey.Y)

	return rawPub, rawPriv, nil
}

type SECP256R1Verifier struct {
	public ecdsa.PublicKey
}

func (s SECP256R1Verifier) Verify(payload, signature []byte) error {
	digest := sha256.Sum256(payload)
	if !ecdsa.VerifyASN1(&s.public, digest[:], signature) {
		return errors.New("biscuit: invalid signature")
	}

	return nil
}

func (s SECP256R1Verifier) Matches(signer Signer) error {
	secpSigner, ok := signer.(*SECP256R1Signer)
	if !ok {
		return errors.New("signer is not secp256r1")
	}

	if !secpSigner.private.PublicKey.Equal(&s.public) {
		return errors.New("signer public key mismatch")
	}

	return nil
}

func (s *SECP256R1Verifier) UnmarshalBinary(data []byte) error {
	p256 := elliptic.P256()

	// https://github.com/eclipse-biscuit/biscuit/blob/main/SPECIFICATIONS.md#ecdsa
	pubX, pubY := elliptic.UnmarshalCompressed(p256, data)
	if pubX == nil {
		return errors.New("invalid public key")
	}

	*s = SECP256R1Verifier{public: ecdsa.PublicKey{
		Curve: p256,
		X:     pubX,
		Y:     pubY,
	}}

	return nil
}
