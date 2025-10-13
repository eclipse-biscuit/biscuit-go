// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package biscuit_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/eclipse-biscuit/biscuit-go/v2"
	"github.com/eclipse-biscuit/biscuit-go/v2/parser"
)

func ExampleBiscuit() {
	rng := rand.Reader
	publicRoot, privateRoot, _ := ed25519.GenerateKey(rng)

	authority, err := parser.FromStringBlockWithParams(`
		right("/a/file1.txt", {read});
		right("/a/file1.txt", {write});
		right("/a/file2.txt", {read});
		right("/a/file3.txt", {write});
	`, map[string]biscuit.Term{"read": biscuit.String("read"), "write": biscuit.String("write")})
	if err != nil {
		panic(fmt.Errorf("failed to parse authority block: %v", err))
	}

	builder := biscuit.NewBuilder(privateRoot)
	builder.AddBlock(authority)

	b, err := builder.Build()
	if err != nil {
		panic(fmt.Errorf("failed to build biscuit: %v", err))
	}

	token, err := b.Serialize()
	if err != nil {
		panic(fmt.Errorf("failed to serialize biscuit: %v", err))
	}

	fmt.Printf("Token1 length: %d\n", len(token))

	deser, err := biscuit.Unmarshal(token)
	if err != nil {
		panic(fmt.Errorf("failed to deserialize biscuit: %v", err))
	}

	blockBuilder := deser.CreateBlock()

	block, err := parser.FromStringBlockWithParams(`
			check if resource($file), operation($permission), [{read}].contains($permission);`,
		map[string]biscuit.Term{"read": biscuit.String("read")})

	if err != nil {
		panic(fmt.Errorf("failed to parse block: %v", err))
	}
	blockBuilder.AddBlock(block)

	b2, err := deser.Append(rng, blockBuilder.Build())
	if err != nil {
		panic(fmt.Errorf("failed to append: %v", err))
	}

	token2, err := b2.Serialize()
	if err != nil {
		panic(fmt.Errorf("failed to serialize biscuit: %v", err))
	}

	fmt.Printf("Token2 length: %d\n", len(token2))

	// Verify
	b2, err = biscuit.Unmarshal(token2)
	if err != nil {
		panic(fmt.Errorf("failed to deserialize token: %v", err))
	}

	v1, err := b2.Authorizer(publicRoot)
	if err != nil {
		panic(fmt.Errorf("failed to create verifier: %v", err))
	}

	authorizer, err := parser.FromStringAuthorizerWithParams(`
		resource({res});
		operation({op});
		allow if right({res}, {op});
		`, map[string]biscuit.Term{"res": biscuit.String("/a/file1.txt"), "op": biscuit.String("read")})

	if err != nil {
		panic(fmt.Errorf("failed to parse authorizer: %v", err))
	}
	v1.AddAuthorizer(authorizer)

	if err := v1.Authorize(); err != nil {
		// fmt.Println(v1.PrintWorld())

		fmt.Println("forbidden to read /a/file1.txt")
	} else {
		//fmt.Println(v1.PrintWorld())

		fmt.Println("allowed to read /a/file1.txt")
	}

	v1, _ = b2.Authorizer(publicRoot)

	authorizer, err = parser.FromStringAuthorizerWithParams(`
		resource({res});
		operation({op});
		allow if right({res}, {op});
		`, map[string]biscuit.Term{"res": biscuit.String("/a/file1.txt"), "op": biscuit.String("write")})

	if err != nil {
		panic(fmt.Errorf("failed to parse authorizer: %v", err))
	}
	v1.AddAuthorizer(authorizer)

	if err := v1.Authorize(); err != nil {
		fmt.Println("forbidden to write /a/file1.txt")
	} else {
		fmt.Println("allowed to write /a/file1.txt")
	}

	// Output: Token1 length: 251
	// Token2 length: 433
	// allowed to read /a/file1.txt
	// forbidden to write /a/file1.txt
}
