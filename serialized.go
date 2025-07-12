// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package biscuit

type SerializedBiscuit struct {
	RootKeyID *uint32
	Authority CryptoBlock
	Blocks    []CryptoBlock
	Proof     TokenNext
}
