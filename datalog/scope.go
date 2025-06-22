// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package datalog

type ScopeType byte

const (
	ScopeTypeAuthority ScopeType = iota
	ScopeTypePrevious
	ScopeTypePublicKey
)

type Scope interface {
	Type() ScopeType
}

type AuthorityScope struct{}

func (AuthorityScope) Type() ScopeType {
	return ScopeTypeAuthority
}

type PreviousScope struct{}

func (PreviousScope) Type() ScopeType {
	return ScopeTypePrevious
}

type PublicKeyScope struct {
	ID uint32
}

func (PublicKeyScope) Type() ScopeType {
	return ScopeTypePublicKey
}
