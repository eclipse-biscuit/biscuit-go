// Copyright (c) 2019 Titanous, daeMOn63 and Contributors to the Eclipse Foundation.
// SPDX-License-Identifier: Apache-2.0

package biscuit

import (
	"fmt"

	"github.com/eclipse-biscuit/biscuit-go/v2/datalog"
	"github.com/eclipse-biscuit/biscuit-go/v2/pb"
	"google.golang.org/protobuf/proto"
)

func protoPublicKeyToTokenPublicKey(pubKey *pb.PublicKey) (*datalog.PublicKey, error) {
	if pubKey == nil {
		return nil, ErrNilPublicKey
	}
	result := datalog.PublicKey{
		Algorithm: pubKey.GetAlgorithm(),
		Key:       pubKey.GetKey(),
	}
	return &result, nil
}

func tokenPublicKeyToProtoPublicKey(pubKey *datalog.PublicKey) (*pb.PublicKey, error) {
	if pubKey == nil {
		return nil, ErrNilPublicKey
	}

	result := pb.PublicKey{
		Algorithm: &pubKey.Algorithm,
		Key:       pubKey.Key,
	}

	return &result, nil
}

func tokenExternalSignatureToProtoExternalSignature(extSig *ExternalSignature) (*pb.ExternalSignature, error) {
	if extSig == nil {
		return nil, ErrNilExternalSignature
	}
	protoPubKey, err := tokenPublicKeyToProtoPublicKey(&extSig.publicKey)
	if err != nil {
		return nil, err
	}
	return &pb.ExternalSignature{
		Signature: extSig.signature,
		PublicKey: protoPubKey,
	}, nil
}

func protoExternalSignatureToTokenExternalSignature(protoExtSig *pb.ExternalSignature) (*ExternalSignature, error) {
	if protoExtSig == nil {
		return nil, ErrNilExternalSignature
	}

	tokenPublicKey, err := protoPublicKeyToTokenPublicKey(protoExtSig.GetPublicKey())
	if err != nil {
		return nil, err
	}

	return &ExternalSignature{
		publicKey: *tokenPublicKey,
		signature: protoExtSig.GetSignature(),
	}, nil
}

func tokenBlockToProtoBlock(input *Block) (*pb.Block, error) {
	out := &pb.Block{
		Symbols: *input.symbols,
		Context: proto.String(input.context),
		Version: proto.Uint32(uint32(input.version)),
	}

	facts := input.facts
	if facts != nil {
		out.FactsV2 = make([]*pb.FactV2, len(facts))
		var err error
		for i, fact := range facts {
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

	if input.checks != nil {
		out.ChecksV2 = make([]*pb.CheckV2, len(input.checks))
		for i, check := range input.checks {
			c, err := tokenCheckToProtoCheckV2(check)
			if err != nil {
				return nil, err
			}
			out.ChecksV2[i] = c
		}
	}

	if input.scopes != nil && len(input.scopes) > 0 {
		out.Scope = make([]*pb.Scope, len(input.scopes))
		for i, scope := range input.scopes {
			s, err := tokenScopeToProtoScope(&scope)
			if err != nil {
				return nil, err
			}
			out.Scope[i] = s
		}
	}

	if input.publicKeys != nil && len(*input.publicKeys) > 0 {
		out.PublicKeys = make([]*pb.PublicKey, len(*input.publicKeys))
		for i, pubKey := range *input.publicKeys {
			out.PublicKeys[i] = &pb.PublicKey{
				Algorithm: &pubKey.Algorithm,
				Key:       pubKey.Key,
			}
		}
	}

	return out, nil
}

func protoBlockToTokenBlock(input *pb.Block, pbExternalSignature *pb.ExternalSignature) (*Block, error) {
	symbols := datalog.SymbolTable(input.Symbols)

	var publicKeys *datalog.PublicKeyTable
	var facts []datalog.Fact
	var rules []datalog.Rule
	var checks []datalog.Check
	var scopes []datalog.Scope
	var externalSignature *ExternalSignature

	datalogVersion, err := getDatalogVersion(input)
	if err != nil {
		return nil, fmt.Errorf("failed parsing block's version: %w", err)
	}

	switch datalogVersion {
	case DatalogVersion3_0, DatalogVersion3_1, DatalogVersion3_2, DatalogVersion3_3:
		facts = make([]datalog.Fact, len(input.FactsV2))
		rules = make([]datalog.Rule, len(input.RulesV2))
		checks = make([]datalog.Check, len(input.ChecksV2))

		if input.PublicKeys != nil && len(input.PublicKeys) > 0 {
			pkTable := make(datalog.PublicKeyTable, 0, len(input.PublicKeys))
			for _, pubKey := range input.PublicKeys {
				pk, err := protoPublicKeyToTokenPublicKey(pubKey)
				if err != nil {
					return nil, err
				}
				_ = pkTable.Insert(*pk)
			}
			publicKeys = &pkTable
		}

		for i, pbFact := range input.FactsV2 {
			dlFact, err := protoFactToTokenFactV2(pbFact)
			if err != nil {
				return nil, err
			}
			facts[i] = *dlFact
		}

		for i, pbRule := range input.RulesV2 {
			dlRule, err := protoRuleToTokenRuleV2(pbRule)
			if err != nil {
				return nil, err
			}
			rules[i] = *dlRule
		}

		for i, pbCheck := range input.ChecksV2 {
			c, err := protoCheckToTokenCheckV2(pbCheck)
			if err != nil {
				return nil, err
			}
			checks[i] = *c
		}

		if input.Scope != nil && len(input.Scope) > 0 {
			scopes = make([]datalog.Scope, len(input.Scope))
			for i, pbScope := range input.Scope {
				s, err := protoScopeToTokenScope(pbScope)
				if err != nil {
					return nil, err
				}
				scopes[i] = *s
			}
		}

		if pbExternalSignature != nil {
			externalSignature, err = protoExternalSignatureToTokenExternalSignature(pbExternalSignature)
			if err != nil {
				return nil, fmt.Errorf("biscuit: failed parsing block's external signature: %w", err)
			}
		}

	default:
		return nil, fmt.Errorf("biscuit: failed to convert proto block to token block: unsupported version: %d", datalogVersion)
	}

	return &Block{
		symbols:           &symbols,
		publicKeys:        publicKeys,
		facts:             facts,
		rules:             rules,
		checks:            checks,
		scopes:            scopes,
		context:           input.GetContext(),
		version:           datalogVersion,
		externalSignature: externalSignature,
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
