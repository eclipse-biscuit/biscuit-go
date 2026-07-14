package crypto

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io"

	"github.com/eclipse-biscuit/biscuit-go/v2/pb"
)

type ED25519Signer struct {
	private ed25519.PrivateKey
}

func NewED25519Signer(private ed25519.PrivateKey) *ED25519Signer {
	return &ED25519Signer{private: private}
}

func (e ED25519Signer) Algorithm() pb.PublicKey_Algorithm {
	return pb.PublicKey_Ed25519
}

func (e ED25519Signer) PublicKeyProto() (*pb.PublicKey, error) {
	pub, ok := e.private.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("ed25519 public key missing")
	}
	return &pb.PublicKey{
		Algorithm: pb.PublicKey_Ed25519.Enum(),
		Key:       pub,
	}, nil
}

func (e ED25519Signer) Sign(payload []byte) ([]byte, error) {
	return ed25519.Sign(e.private, payload), nil
}

func (e *ED25519Signer) UnmarshalBinary(data []byte) error {
	if e == nil {
		return errors.New("UnmarshalBinary called with nil")
	}

	if len(data) != ed25519.SeedSize {
		return errors.New("biscuit: invalid key size")
	}

	*e = ED25519Signer{private: ed25519.NewKeyFromSeed(data)}

	return nil
}

type ED25519Generator struct{}

func (e ED25519Generator) GenerateNext(rng io.Reader) ([]byte, []byte, error) {
	pub, priv, err := ed25519.GenerateKey(rng)
	if err != nil {
		return nil, nil, err
	}

	return pub, priv.Seed(), nil
}

type ED25519Verifier struct {
	public ed25519.PublicKey
}

func NewED25519Verifier(public ed25519.PublicKey) *ED25519Verifier {
	return &ED25519Verifier{public: public}
}

func (e *ED25519Verifier) UnmarshalBinary(data []byte) error {
	if e == nil {
		return errors.New("UnmarshalBinary called with nil")
	}

	if len(data) != ed25519.PublicKeySize {
		return errors.New("biscuit: invalid key size")
	}

	*e = ED25519Verifier{public: data}

	return nil
}

func (e ED25519Verifier) Verify(payload, signature []byte) error {
	if !ed25519.Verify(e.public, payload, signature) {
		return errors.New("biscuit: invalid signature")
	}
	return nil
}

func (e ED25519Verifier) Matches(signer Signer) error {
	edSigner, ok := signer.(*ED25519Signer)
	if !ok {
		return errors.New("signer is not ED25519")
	}

	pub, ok := edSigner.private.Public().(ed25519.PublicKey)
	if !ok {
		return errors.New("signer public key is not ED25519")
	}

	if !bytes.Equal(e.public, pub) {
		return errors.New("signer public key mismatch")
	}

	return nil
}
