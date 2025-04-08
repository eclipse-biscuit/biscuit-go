// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package biscuit

import "io"

type compositionOption interface {
	builderOption
	biscuitOption
}

type rngOption struct {
	io.Reader
}

func (o rngOption) applyToBuilder(b *builderOptions) {
	if r := o.Reader; r != nil {
		b.rng = o
	}
}

func (o rngOption) applyToBiscuit(b *biscuitOptions) error {
	if r := o.Reader; r != nil {
		b.rng = r
	}
	return nil
}

// WithRNG supplies a random number generator as a byte stream from which to read when generating
// key pairs with which to sign blocks within biscuits.
func WithRNG(r io.Reader) compositionOption {
	return rngOption{r}
}

type rootKeyIDOption uint32

func (o rootKeyIDOption) applyToBuilder(b *builderOptions) {
	id := uint32(o)
	b.rootKeyID = &id
}

func (o rootKeyIDOption) applyToBiscuit(b *biscuitOptions) error {
	id := uint32(o)
	b.rootKeyID = &id
	return nil
}

// WithRootKeyID specifies the identifier for the root key pair used to sign a biscuit's authority
// block, allowing a consuming party to later select the corresponding public key to validate that
// signature.
func WithRootKeyID(id uint32) compositionOption {
	return rootKeyIDOption(id)
}
