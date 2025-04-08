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
		Symbols: *input.symbols,
		Context: proto.String(input.context),
		Version: proto.Uint32(input.version),
	}

	facts := input.facts
	if facts != nil {
		out.FactsV2 = make([]*pb.FactV2, len(*facts))
		var err error
		for i, fact := range *facts {
			out.FactsV2[i], err = tokenFactToProtoFactV2(fact)
			if err != nil {
				return nil, err
			}
		}
	}

	rules := input.rules
	if rules != nil {
		out.RulesV2 = make([]*pb.RuleV2, len(rules))
		for i, rule := range rules {
			r, err := tokenRuleToProtoRuleV2(rule)
			if err != nil {
				return nil, err
			}
			out.RulesV2[i] = r
		}
	}

	checks := input.checks
	if checks != nil {
		out.ChecksV2 = make([]*pb.CheckV2, len(checks))
		for i, check := range checks {
			c, err := tokenCheckToProtoCheckV2(check)
			if err != nil {
				return nil, err
			}
			out.ChecksV2[i] = c
		}
	}

	return out, nil
}

func protoBlockToTokenBlock(input *pb.Block) (*Block, error) {
	symbols := datalog.SymbolTable(input.Symbols)

	var facts datalog.FactSet
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
		facts = make(datalog.FactSet, len(input.FactsV2))
		rules = make([]datalog.Rule, len(input.RulesV2))
		checks = make([]datalog.Check, len(input.ChecksV2))

		for i, pbFact := range input.FactsV2 {
			f, err := protoFactToTokenFactV2(pbFact)
			if err != nil {
				return nil, err
			}
			facts[i] = *f
		}

		for i, pbRule := range input.RulesV2 {
			r, err := protoRuleToTokenRuleV2(pbRule)
			if err != nil {
				return nil, err
			}
			rules[i] = *r
		}

		for i, pbCheck := range input.ChecksV2 {
			c, err := protoCheckToTokenCheckV2(pbCheck)
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
		facts:   &facts,
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
