// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package biscuit

import (
	"testing"
	"time"

	"github.com/biscuit-auth/biscuit-go/v2/datalog"
	"github.com/stretchr/testify/require"
)

func TestFromDatalogFact(t *testing.T) {
	now := time.Now()

	symbolTable := &datalog.SymbolTable{"sym0", "sym1", "var1"}
	dlFact := datalog.Fact{
		Predicate: datalog.Predicate{
			Name: datalog.String(datalog.OFFSET + 0),
			Terms: []datalog.Term{
				datalog.String(datalog.OFFSET + 1),
				datalog.Integer(42),
				symbolTable.Insert("foo"),
				datalog.Variable(datalog.OFFSET + 2),
				datalog.Date(now.Unix()),
				datalog.Bytes([]byte("some random bytes")),
				datalog.Bool(true),
				datalog.Bool(false),
				datalog.Set{
					symbolTable.Insert("abc"),
					datalog.Integer(42),
					datalog.String(datalog.OFFSET + 1),
				},
			},
		},
	}

	fact, err := fromDatalogFact(symbolTable, dlFact)
	require.NoError(t, err)

	expectedFact := &Fact{
		Predicate: Predicate{
			Name: "sym0",
			IDs: []Term{
				String("sym1"),
				Integer(42),
				String("foo"),
				Variable("var1"),
				Date(time.Unix(now.Unix(), 0)),
				Bytes([]byte("some random bytes")),
				Bool(true),
				Bool(false),
				Set{String("abc"), Integer(42), String("sym1")},
			},
		},
	}
	require.Equal(t, expectedFact, fact)
}
