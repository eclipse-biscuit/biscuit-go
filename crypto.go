// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package biscuit

import (
	"crypto/ed25519"
	"io"
)

type Algorithm byte

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

type Ed25519PrivateKey struct {
	Key ed25519.PrivateKey
}

func (k *Ed25519PrivateKey) Algorithm() Algorithm {
	return AlgorithmEd25519
}

func (k *Ed25519PrivateKey) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(k.Key, message), nil
}

func NewEd25519KeyPair(rng io.Reader) (PublicKey, PrivateKey, error) {
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

type SealTokenNext struct {
	Signature []byte
}
