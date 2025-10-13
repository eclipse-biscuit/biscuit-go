// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package biscuit_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/eclipse-biscuit/biscuit-go/v2/parser"
)

// code examples for the documentation at https://www.biscuitsec.org
// if these functions change, please send a PR at https://github.com/eclipse-biscuit/website

func CreateKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	rng := rand.Reader
	publicRoot, privateRoot, _ := ed25519.GenerateKey(rng)
	return publicRoot, privateRoot
}

func CreateToken(root *ed25519.PrivateKey) (*biscuit.Biscuit, error) {
	builder := biscuit.NewBuilder(*root)

	fact, err := parser.FromStringFact(`user("1234")`)
	if err != nil {
		return nil, fmt.Errorf("failed to parse authority facts: %v", err)
	}
	err = builder.AddAuthorityFact(fact)
	if err != nil {
		return nil, fmt.Errorf("failed to add authority facts: %v", err)
	}

	check, err := parser.FromStringCheck(`check if operation("read")`)
	if err != nil {
		return nil, fmt.Errorf("failed to parse authority checks: %v", err)
	}
	err = builder.AddAuthorityCheck(check)
	if err != nil {
		return nil, fmt.Errorf("failed to add authority checks: %v", err)
	}

	token, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build biscuit: %v", err)
	}

	return token, nil
}

func Authorize(token *biscuit.Biscuit, root *ed25519.PublicKey) error {
	authorizer, err := token.Authorizer(*root)
	if err != nil {
		return fmt.Errorf("failed to create verifier: %v", err)
	}

	fact1, err := parser.FromStringFact(`resource("/a/file1.txt")`)
	if err != nil {
		return fmt.Errorf("failed to parse verifier fact: %v", err)
	}
	authorizer.AddFact(fact1)

	fact2, err := parser.FromStringFact(`operation("read")`)
	if err != nil {
		return fmt.Errorf("failed to parse verifier fact: %v", err)
	}
	authorizer.AddFact(fact2)

	policy, err := parser.FromStringPolicy(`allow if resource("/a/file1.txt")`)
	if err != nil {
		return fmt.Errorf("failed to parse verifier policy: %v", err)
	}
	authorizer.AddPolicy(policy)

	return authorizer.Authorize()
}

func Attenuate(serializedToken []byte, root *ed25519.PublicKey) ([]byte, error) {
	token, err := biscuit.Unmarshal(serializedToken)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize biscuit: %v", err)
	}

	blockBuilder := token.CreateBlock()

	check, err := parser.FromStringCheck(`check if resource($file), operation($permission), ["read"].contains($permission)`)
	if err != nil {
		return nil, fmt.Errorf("failed to parse check: %v", err)
	}
	err = blockBuilder.AddCheck(check)
	if err != nil {
		return nil, fmt.Errorf("failed to add block check: %v", err)
	}

	rng := rand.Reader
	token2, err := token.Append(rng, blockBuilder.Build())
	if err != nil {
		return nil, fmt.Errorf("failed to append: %v", err)
	}

	return token2.Serialize()
}

func Seal(b *biscuit.Biscuit, rng io.Reader) (*biscuit.Biscuit, error) {
	return b.Seal(rng)
}

func Query(authorizer biscuit.Authorizer) (biscuit.FactSet, error) {
	rule, err := parser.FromStringRule(`data($name, $id) <- user($name, $id`)
	if err != nil {
		return nil, fmt.Errorf("failed to parse check: %v", err)
	}

	return authorizer.Query(rule)
}
