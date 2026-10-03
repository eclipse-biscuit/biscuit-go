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

	vb, err := b.Authorizer(publicRoot)
	require.NoError(t, err)

	vb.AddPolicy(DefaultDenyPolicy)

	v1, err := vb.Build()
	require.NoError(t, err)
	err = v1.Authorize()
	require.ErrorIs(t, err, ErrPolicyDenied)

	v2, err := vb.Build()
	require.NoError(t, err)
	err = v2.Authorize()
	require.ErrorIs(t, err, ErrPolicyDenied)

	// Create fresh builder for allow policy test
	vb3, err := b.Authorizer(publicRoot)
	require.NoError(t, err)
	vb3.AddPolicy(DefaultAllowPolicy)

	v3, err := vb3.Build()
	require.NoError(t, err)
	err = v3.Authorize()
	require.NoError(t, err)
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

	vb, err := b.Authorizer(publicRoot)
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

	vb.AddPolicy(policy)
	vb.AddFact(
		Fact{Predicate: Predicate{
			Name: "operation",
			IDs:  []Term{String("read")}}},
	)
	vb.AddFact(
		Fact{Predicate: Predicate{
			Name: "resource",
			IDs:  []Term{String("some_file.txt")}}},
	)

	v1, err := vb.Build()
	require.NoError(t, err)

	require.NoError(t, v1.Authorize())

	vb, err = b.Authorizer(publicRoot)
	require.NoError(t, err)
	vb.AddPolicy(policy)
	vb.AddFact(
		Fact{Predicate: Predicate{
			Name: "operation",
			IDs:  []Term{String("write")}}},
	)
	vb.AddFact(
		Fact{Predicate: Predicate{
			Name: "resource",
			IDs:  []Term{String("some_file.txt")}}},
	)

	v2, err := vb.Build()
	require.NoError(t, err)

	require.Equal(t, v2.Authorize(), ErrNoMatchingPolicy)
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

	require.Equal(t, v1.(*authorizerBuilder).authorizerFacts, v2.(*authorizerBuilder).authorizerFacts)
	require.Equal(t, v1.(*authorizerBuilder).authorizerRules, v2.(*authorizerBuilder).authorizerRules)
	require.Equal(t, v1.(*authorizerBuilder).authorizerChecks, v2.(*authorizerBuilder).authorizerChecks)
	require.Equal(t, v1.(*authorizerBuilder).authorizerPolicies, v2.(*authorizerBuilder).authorizerPolicies)
}
