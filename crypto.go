// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package biscuit

import (
	"crypto/ed25519"
	"errors"
	"io"
)

type Algorithm int32

const (
	AlgorithmEd25519 Algorithm = 0
)

type PublicKey interface {
	Algorithm() Algorithm
	Verify(message []byte, signature []byte) bool
	Serialize() []byte
}

type PrivateKey interface {
	Algorithm() Algorithm
	Sign(message []byte) ([]byte, error)
	PublicKey() PublicKey
}

type SerializablePrivateKey interface {
	Algorithm() Algorithm
	Serialize() []byte
}

type Ed25519PublicKey struct {
	Key ed25519.PublicKey
}

func (k *Ed25519PublicKey) Algorithm() Algorithm {
	return AlgorithmEd25519
}

func (k *Ed25519PublicKey) Verify(message []byte, signature []byte) bool {
	return ed25519.Verify(k.Key, message, signature)
}

func (k *Ed25519PublicKey) Serialize() []byte {
	return k.Key
}

func Ed25519PublicKeyDeserialize(data []byte) (*Ed25519PublicKey, error) {
	if len(data) != ed25519.PublicKeySize {
		return nil, errors.New("invalid public key size")
	}
	return &Ed25519PublicKey{Key: data}, nil
}

type Ed25519PrivateKey struct {
	Key ed25519.PrivateKey
}

func (k *Ed25519PrivateKey) Algorithm() Algorithm {
	return AlgorithmEd25519
}

func (k *Ed25519PrivateKey) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(k.Key, message), nil
}

func (k *Ed25519PrivateKey) PublicKey() PublicKey {
	return &Ed25519PublicKey{Key: k.Key.Public().(ed25519.PublicKey)}
}

func (k *Ed25519PrivateKey) Serialize() []byte {
	return k.Key.Seed()
}

func Ed25519PrivateKeyDeserialize(data []byte) (*Ed25519PrivateKey, error) {
	if len(data) != ed25519.SeedSize {
		return nil, errors.New("invalid seed size")
	}
	return &Ed25519PrivateKey{Key: ed25519.NewKeyFromSeed(data)}, nil
}

func NewEd25519KeyPair(rng io.Reader) (*Ed25519PublicKey, *Ed25519PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rng)
	if err != nil {
		return nil, nil, err
	}
	return &Ed25519PublicKey{Key: pub}, &Ed25519PrivateKey{Key: priv}, nil
}

type CryptoBlock struct {
	Data              []byte
	NextKey           PublicKey
	Signature         []byte
	ExternalSignature *ExternalSignature
	Version           uint32
}

type ExternalSignature struct {
	PublicKey PublicKey
	Signature []byte
}

type TokenNextType byte

const (
	TokenNextTypeSecret TokenNextType = iota
	TokenNextTypeSeal
)

type TokenNext interface {
	Type() TokenNextType
}

type SecretTokenNext struct {
	Key PrivateKey
}

func (t *SecretTokenNext) Type() TokenNextType {
	return TokenNextTypeSecret
}

type SealTokenNext struct {
	Signature []byte
}

func (t *SealTokenNext) Type() TokenNextType {
	return TokenNextTypeSeal
}
