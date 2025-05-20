// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package biscuit

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVerifierDefaultPolicy(t *testing.T) {
	rng := rand.Reader
	publicRoot, privateRoot, _ := ed25519.GenerateKey(rng)

	builder := NewBuilder(privateRoot)
	err := builder.AddAuthorityFact(Fact{Predicate{
		Name: "right",
		IDs: []Term{
			String("/a/file1.txt"),
			String("read"),
		},
	}})
	require.NoError(t, err)

	b, err := builder.Build()
	require.NoError(t, err)

	v, err := b.Authorizer(publicRoot)
	require.NoError(t, err)

	v.AddPolicy(DefaultDenyPolicy)
	err = v.Authorize()
	require.Equal(t, err, ErrPolicyDenied)

	v.Reset()
	v.AddPolicy(DefaultAllowPolicy)
	require.NoError(t, v.Authorize())
}

func TestVerifierPolicies(t *testing.T) {
	rng := rand.Reader
	publicRoot, privateRoot, _ := ed25519.GenerateKey(rng)

	builder := NewBuilder(privateRoot)
	err := builder.AddAuthorityRule(Rule{
		Head: Predicate{Name: "right", IDs: []Term{Variable("file"), Variable("operation")}},
		Body: []Predicate{
			{Name: "resource", IDs: []Term{Variable("file")}},
			{Name: "operation", IDs: []Term{Variable("operation")}},
		},
	})
	require.NoError(t, err)

	b, err := builder.Build()
	require.NoError(t, err)

	v, err := b.Authorizer(publicRoot)
	require.NoError(t, err)

	policy := Policy{Kind: PolicyKindAllow, Queries: []Rule{
		{
			Head: Predicate{Name: "allow_read"},
			Body: []Predicate{
				{Name: "right", IDs: []Term{Variable("file"), Variable("operation")}},
			},
			Expressions: []Expression{
				{
					Value{Term: Variable("operation")},
					Value{Term: String("read")},
					BinaryEqual,
				},
			},
		},
	}}

	v.AddPolicy(policy)
	v.AddFact(Fact{Predicate: Predicate{
		Name: "operation",
		IDs:  []Term{String("read")},
	}})
	v.AddFact(Fact{Predicate: Predicate{
		Name: "resource",
		IDs:  []Term{String("some_file.txt")},
	}})

	require.NoError(t, v.Authorize())

	v, err = b.Authorizer(publicRoot)
	require.NoError(t, err)
	v.AddPolicy(policy)
	v.AddFact(Fact{Predicate: Predicate{
		Name: "operation",
		IDs:  []Term{String("write")},
	}})
	v.AddFact(Fact{Predicate: Predicate{
		Name: "resource",
		IDs:  []Term{String("some_file.txt")},
	}})
	require.Equal(t, v.Authorize(), ErrNoMatchingPolicy)
}

func TestVerifierSerializeLoad(t *testing.T) {
	rng := rand.Reader
	publicRoot, privateRoot, _ := ed25519.GenerateKey(rng)

	builder := NewBuilder(privateRoot)
	b, err := builder.Build()
	require.NoError(t, err)

	v1, err := b.Authorizer(publicRoot)
	require.NoError(t, err)

	policy := Policy{Kind: PolicyKindAllow, Queries: []Rule{
		{
			Head: Predicate{Name: "allow_read", IDs: []Term{Variable("file"), Variable("operation")}},
			Body: []Predicate{
				{Name: "right", IDs: []Term{Variable("file"), Variable("operation")}},
			},
			Expressions: []Expression{
				{
					Value{Term: Variable("operation")},
					Value{Term: String("read")},
					BinaryEqual,
				},
			},
		},
	}}

	fact1 := Fact{Predicate: Predicate{
		Name: "operation",
		IDs:  []Term{String("read")},
	}}
	fact2 := Fact{Predicate: Predicate{
		Name: "resource",
		IDs:  []Term{String("some_file.txt")},
	}}
	rule1 := Rule{
		Head: Predicate{Name: "rule1", IDs: []Term{Variable("test")}},
		Body: []Predicate{
			{Name: "resource", IDs: []Term{String("some_file.txt")}},
		},
		Expressions: []Expression{
			{Value{Term: Integer(1)}, Value{Term: Integer(2)}, BinaryLessThan},
		},
	}
	check1 := Check{Queries: []Rule{rule1}}

	v1.AddFact(fact1)
	v1.AddFact(fact2)
	v1.AddRule(rule1)
	v1.AddCheck(check1)
	v1.AddPolicy(policy)
	s, err := v1.SerializePolicies()
	require.NoError(t, err)

	v2, err := b.Authorizer(publicRoot)
	require.NoError(t, err)

	require.NoError(t, v2.LoadPolicies(s))

	require.Equal(t, v1.(*authorizer).world.Facts(), v2.(*authorizer).world.Facts())
	require.Equal(t, v1.(*authorizer).world.Rules(), v2.(*authorizer).world.Rules())
	require.Equal(t, v1.(*authorizer).checks, v2.(*authorizer).checks)
	require.Equal(t, v1.(*authorizer).policies, v2.(*authorizer).policies)
}
