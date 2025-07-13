// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package biscuit

import (
	"fmt"

	"github.com/biscuit-auth/biscuit-go/v2/datalog"
	"github.com/biscuit-auth/biscuit-go/v2/pb"
	"google.golang.org/protobuf/proto"
)

func tokenBlockToProtoBlock(input *Block) (*pb.Block, error) {
	out := &pb.Block{
		Symbols: input.symbols.Symbols,
		Context: proto.String(input.context),
		Version: proto.Uint32(input.version),
	}

	facts := input.facts
	if facts != nil {
		out.Facts = make([]*pb.Fact, len(facts))
		var err error
		for i, fact := range facts {
			out.Facts[i], err = tokenFactToProtoFact(fact)
			if err != nil {
				return nil, err
			}
		}
	}

	rules := input.rules
	if rules != nil {
		out.Rules = make([]*pb.Rule, len(rules))
		for i, rule := range rules {
			r, err := tokenRuleToProtoRule(rule)
			if err != nil {
				return nil, err
			}
			out.Rules[i] = r
		}
	}

	checks := input.checks
	if checks != nil {
		out.Checks = make([]*pb.Check, len(checks))
		for i, check := range checks {
			c, err := tokenCheckToProtoCheck(check)
			if err != nil {
				return nil, err
			}
			out.Checks[i] = c
		}
	}

	return out, nil
}

func protoBlockToTokenBlock(input *pb.Block) (*Block, error) {
	symbols := datalog.SymbolTable{Symbols: input.Symbols}

	var facts []datalog.Fact
	var rules []datalog.Rule
	var checks []datalog.Check

	if input.GetVersion() < MinSchemaVersion {
		return nil, fmt.Errorf(
			"biscuit: failed to convert proto block to token block: block version: %d < library version %d",
			input.GetVersion(),
			MinSchemaVersion,
		)
	}
	if input.GetVersion() > MaxSchemaVersion {
		return nil, fmt.Errorf(
			"biscuit: failed to convert proto block to token block: block version: %d > library version %d",
			input.GetVersion(),
			MaxSchemaVersion,
		)
	}

	switch input.GetVersion() {
	case 3:
		facts = make([]datalog.Fact, len(input.Facts))
		rules = make([]datalog.Rule, len(input.Rules))
		checks = make([]datalog.Check, len(input.Checks))

		for i, pbFact := range input.Facts {
			f, err := protoFactToTokenFact(pbFact)
			if err != nil {
				return nil, err
			}
			facts[i] = *f
		}

		for i, pbRule := range input.Rules {
			r, err := protoRuleToTokenRule(pbRule)
			if err != nil {
				return nil, err
			}
			rules[i] = *r
		}

		for i, pbCheck := range input.Checks {
			c, err := protoCheckToTokenCheck(pbCheck)
			if err != nil {
				return nil, err
			}
			checks[i] = *c
		}
	default:
		return nil, fmt.Errorf("biscuit: failed to convert proto block to token block: unsupported version: %d", input.GetVersion())
	}

	return &Block{
		symbols: &symbols,
		facts:   facts,
		rules:   rules,
		checks:  checks,
		context: input.GetContext(),
		version: input.GetVersion(),
	}, nil
}

/*func tokenSignatureToProtoSignature(ts *sig.TokenSignature) *pb.Signature {
	params, z := ts.Encode()
	return &pb.Signature{
		Parameters: params,
		Z:          z,
	}
}

func protoSignatureToTokenSignature(ps *pb.Signature) (*sig.TokenSignature, error) {
	return sig.Decode(ps.Parameters, ps.Z)
}*/
