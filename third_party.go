package biscuit

import (
	"crypto"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/eclipse-biscuit/biscuit-go/v2/datalog"
	biscuitcrypto "github.com/eclipse-biscuit/biscuit-go/v2/internal/crypto"
	"github.com/eclipse-biscuit/biscuit-go/v2/pb"
)

// The v3.3 specification dictates that all third party blocks should use block signature version v1.
const blockSignatureVersionForThirdPartyBlocks = BlockSignatureVersion1

// The v3.3 specification dictates that the minimum Datalog version used for a third party block must be v3.2 (int 5).
const minimumDatalogVersionForThirdPartyBlocks = DatalogVersion3_2

type ThirdPartyBlockRequest struct {
	previousSignature []byte
}

type ThirdPartyBlockContents struct {
	payload           []byte
	externalSignature *pb.ExternalSignature
}

func UnmarshalThirdPartyBlockContents(bytes []byte) (ThirdPartyBlockContents, error) {
	var none ThirdPartyBlockContents
	var contentsProto pb.ThirdPartyBlockContents
	err := proto.Unmarshal(bytes, &contentsProto)
	if err != nil {
		return none, fmt.Errorf("failed unmarshaling third party block contents from protobuf: %w", err)
	}
	contents := ThirdPartyBlockContents{
		payload:           contentsProto.GetPayload(),
		externalSignature: contentsProto.GetExternalSignature(),
	}
	if len(contents.payload) == 0 {
		return none, errors.New("third party block contents message includes an empty payload")
	}
	if contents.externalSignature == nil {
		return none, errors.New("third party block contents message had an empty external signature field")
	}
	if len(contents.externalSignature.GetSignature()) == 0 {
		return none, errors.New("third party block contents message's external signature included an empty signature field")
	}
	if len(contents.externalSignature.GetPublicKey().GetKey()) == 0 {
		return none, errors.New("third party block contents message's external signature did not include a public key")
	}
	return contents, nil
}

func (c ThirdPartyBlockContents) toBlock(blockID uint64) (*Block, error) {
	var protoBlock pb.Block
	err := proto.Unmarshal(c.payload, &protoBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal third party block: %w", err)
	}

	block, err := protoBlockToTokenBlock(&protoBlock, c.externalSignature)
	if err != nil {
		return nil, fmt.Errorf("failed to Convert third party block: %w", err)
	}

	// From [v3.3 of the Biscuit specification](https://github.com/eclipse-biscuit/biscuit/blob/c5697d4e41660d5ed461adf0caaaa132c9f29437/SPECIFICATIONS.md#L1228-L1228):
	//
	// > Third-party blocks must at least have datalog version `3.2` (implementations not supporting at least version
	// > `3.2` have different symbol tables mechanisms and may interpret third-party blocks incorrectly).
	if block.version < minimumDatalogVersionForThirdPartyBlocks {
		return nil, fmt.Errorf("third-party block must have at least datalog version 3.2 (encoded as %d), got %d", minimumDatalogVersionForThirdPartyBlocks, block.version)
	}

	tokenExternalSignature, err := protoExternalSignatureToTokenExternalSignature(
		c.externalSignature,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to Convert third party block external signature: %w", err)
	}

	block.externalSignature = tokenExternalSignature

	return block, nil
}

func (c ThirdPartyBlockContents) Serialize() ([]byte, error) {
	contentsProto := &pb.ThirdPartyBlockContents{
		Payload:           c.payload,
		ExternalSignature: c.externalSignature,
	}
	contentsBytes, err := proto.Marshal(contentsProto)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize third party block contents as a protobuf message: %w", err)
	}
	return contentsBytes, nil
}

func (req *ThirdPartyBlockRequest) Serialize() ([]byte, error) {
	request := pb.ThirdPartyBlockRequest{
		PreviousSignature: req.previousSignature,
	}

	return proto.Marshal(&request)
}

// UnmarshalThirdPartyBlockRequest deserializes the given byte string into a ThirdPartyBlockRequest.
func UnmarshalThirdPartyBlockRequest(slice []byte) (ThirdPartyBlockRequest, error) {
	var none ThirdPartyBlockRequest
	var pbReq pb.ThirdPartyBlockRequest
	if err := proto.Unmarshal(slice, &pbReq); err != nil {
		return none, err
	}

	if len(pbReq.LegacyPublicKeys) != 0 {
		return none, errors.New("third_party: unsupported legacy public keys were provided in third-party request")
	}

	if pbReq.LegacyPreviousKey != nil {
		return none, errors.New("third_party: unsupported legacy previous public key was provided in third-party block request")
	}

	previousSignature := pbReq.PreviousSignature

	return ThirdPartyBlockRequest{previousSignature: previousSignature}, nil
}

// SignRequest uses the given private key to sign the block created using the given BlockBuilder with respect to the
// given ThirdPartyBlockRequest. This produces a ThirdPartyBlockContents instance, which is bound to the given request,
// covers the built block, and signed by the given signer.
func (req *ThirdPartyBlockRequest) SignRequest(signer crypto.Signer, blockBuilder BlockBuilder) (ThirdPartyBlockContents, error) {
	var none ThirdPartyBlockContents

	biscuitSigner, err := biscuitcrypto.NewSigner(signer)
	if err != nil {
		return none, fmt.Errorf("third party: failed adapting signer: %w", err)
	}

	// Third-party blocks are created independently, so start with fresh tables
	symbols := datalog.SymbolTable{}
	publicKeys := *datalog.NewPublicKeyTable()
	signatureRegistry := datalog.SignatureRegistry{}

	block := blockBuilder.Build(symbols, publicKeys, signatureRegistry)

	protoBlock, err := tokenBlockToProtoBlock(block)
	if err != nil {
		return none, fmt.Errorf("third_party: unable to convert token: %w", err)
	}
	toBeSignedPayload, err := proto.Marshal(protoBlock)
	if err != nil {
		return none, fmt.Errorf("third_party: unable to serialize token: %w", err)
	}

	signature, err := biscuitSigner.Sign(externalSignaturePayloadV1(toBeSignedPayload, req.previousSignature, BlockSignatureVersion1))
	if err != nil {
		return none, fmt.Errorf("third_party: %w", err)
	}

	pubKey, err := biscuitSigner.PublicKeyProto()
	if err != nil {
		return none, fmt.Errorf("third_party: unable to marshal public key to proto: %w", err)
	}

	return ThirdPartyBlockContents{
		payload: toBeSignedPayload,
		externalSignature: &pb.ExternalSignature{
			Signature: signature,
			PublicKey: pubKey,
		},
	}, nil
}
