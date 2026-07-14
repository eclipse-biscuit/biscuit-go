package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"fmt"
	"io"

	"github.com/eclipse-biscuit/biscuit-go/v2/pb"
)

// TODO "Verifier" name is overloaded, since it's used for biscuit evaluation
type Verifier interface {
	Verify(payload, signature []byte) error
	Matches(signer Signer) error
}

type Signer interface {
	// Sign the raw payload, returning the signature or an error. The Signer is responsible for computing the digest of
	// the payload, if necessary.
	Sign(payload []byte) ([]byte, error)
	// Algorithm is only used to derive algorithm for subsequent blocks, since you currently cannot have heterogeneous
	// signature algorithm in same biscuit. It will be removed as breaking changes are made to [biscuit.Biscuit] and
	// [biscuit.Builder].
	Algorithm() pb.PublicKey_Algorithm
	PublicKeyProto() (*pb.PublicKey, error)
}

type KeyGenerator interface {
	GenerateNext(rng io.Reader) (pub, priv []byte, err error)
}

func NewSignerFromPB(alg pb.PublicKey_Algorithm, rawPrivateKey []byte) (Signer, error) {
	switch alg {
	case pb.PublicKey_Ed25519:
		var signer ED25519Signer
		if err := signer.UnmarshalBinary(rawPrivateKey); err != nil {
			return nil, fmt.Errorf("decoding ed25519 signer: %w", err)
		}
		return &signer, nil

	case pb.PublicKey_SECP256R1:
		var signer SECP256R1Signer
		if err := signer.UnmarshalBinary(rawPrivateKey); err != nil {
			return nil, fmt.Errorf("decoding secp256r1 signer: %w", err)
		}
		return &signer, nil

	default:
		return nil, fmt.Errorf("biscuit: unsupported signature algorithm: %s", alg)
	}
}

func NewSigner(signer crypto.Signer) (Signer, error) {
	switch cs := signer.(type) {
	case ed25519.PrivateKey:
		return NewED25519Signer(cs), nil

	case *ecdsa.PrivateKey:
		return &SECP256R1Signer{private: cs}, nil

	default:
		return nil, fmt.Errorf("biscuit: unsupported signing algorithm: %T", signer)
	}
}

func NewKeyGenerator(alg pb.PublicKey_Algorithm) (KeyGenerator, error) {
	switch alg {
	case pb.PublicKey_Ed25519:
		return ED25519Generator{}, nil

	case pb.PublicKey_SECP256R1:
		return SECP256R1Generator{}, nil

	default:
		return nil, fmt.Errorf("biscuit: unsupported key algorithm: %s", alg)
	}
}

func NewVerifierFromPB(alg pb.PublicKey_Algorithm, rawPublicKey []byte) (Verifier, error) {
	switch alg {
	case pb.PublicKey_Ed25519:
		var v ED25519Verifier
		if err := v.UnmarshalBinary(rawPublicKey); err != nil {
			return nil, fmt.Errorf("decoding ed25519 verifier: %w", err)
		}
		return &v, nil

	case pb.PublicKey_SECP256R1:
		var v SECP256R1Verifier
		if err := v.UnmarshalBinary(rawPublicKey); err != nil {
			return nil, fmt.Errorf("decoding secp256r1 verifier: %w", err)
		}
		return &v, nil

	default:
		return nil, fmt.Errorf("biscuit: unsupported key algorithm: %s", alg)
	}
}

// NewSigVerifier returns a biscuit signature Verifier instance wrapping the given public key.
//
// Two public key types are currently supported:
//   - ed25519.PublicKey
//   - *ecdsa.PublicKey
func NewSigVerifier(public crypto.PublicKey) (Verifier, error) {
	switch pub := public.(type) {
	case ed25519.PublicKey:
		return NewED25519Verifier(pub), nil

	case *ecdsa.PublicKey:
		if pub == nil {
			return nil, fmt.Errorf("biscuit: nil public key")
		}
		return &SECP256R1Verifier{public: *pub}, nil

	default:
		return nil, fmt.Errorf("biscuit: unsupported public key type %T", public)
	}
}
