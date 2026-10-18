package main

import (
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func (c *VanetAuth) RegisterRoot(ctx contractapi.TransactionContextInterface, epoch, merkleRoot, validUntil string) (Root, error) {
	if _, err := requireRole(ctx, roleTA); err != nil {
		return Root{}, err
	}
	epochValue, err := parseIntArg("epoch", epoch)
	if err != nil {
		return Root{}, err
	}
	if epochValue < 0 {
		return Root{}, errf("ERR_BAD_INPUT", "epoch must be non-negative")
	}
	if err := validateHex64("merkleRoot", merkleRoot); err != nil {
		return Root{}, err
	}
	validUntilValue, err := parseIntArg("validUntil", validUntil)
	if err != nil {
		return Root{}, err
	}
	now, err := nowMs(ctx)
	if err != nil {
		return Root{}, err
	}
	if validUntilValue <= now {
		return Root{}, errf("ERR_BAD_INPUT", "validUntil must be in the future")
	}

	key, err := rootKey(ctx.GetStub(), epochValue)
	if err != nil {
		return Root{}, err
	}
	existing, err := ctx.GetStub().GetState(key)
	if err != nil {
		return Root{}, err
	}
	if len(existing) != 0 {
		return Root{}, errf("ERR_CONFLICT", "root epoch %d already exists", epochValue)
	}
	root := Root{
		Epoch:        epochValue,
		MerkleRoot:   merkleRoot,
		ValidUntil:   validUntilValue,
		RegisteredTs: now,
	}
	encoded, err := marshalState(root)
	if err != nil {
		return Root{}, err
	}
	if err := ctx.GetStub().PutState(key, encoded); err != nil {
		return Root{}, err
	}
	return root, nil
}

func (c *VanetAuth) GetRoot(ctx contractapi.TransactionContextInterface, epoch string) (Root, error) {
	epochValue, err := parseIntArg("epoch", epoch)
	if err != nil {
		return Root{}, err
	}
	if epochValue < 0 {
		return Root{}, errf("ERR_BAD_INPUT", "epoch must be non-negative")
	}
	key, err := rootKey(ctx.GetStub(), epochValue)
	if err != nil {
		return Root{}, err
	}
	encoded, err := ctx.GetStub().GetState(key)
	if err != nil {
		return Root{}, err
	}
	if len(encoded) == 0 {
		return Root{}, errf("ERR_NOT_FOUND", "root epoch %d was not found", epochValue)
	}
	var root Root
	if err := unmarshalState(encoded, &root); err != nil {
		return Root{}, err
	}
	return root, nil
}

func (c *VanetAuth) ListRoots(ctx contractapi.TransactionContextInterface) ([]Root, error) {
	roots := make([]Root, 0)
	now, err := nowMs(ctx)
	if err != nil {
		return roots, err
	}
	iterator, err := partialCompositeKey(ctx.GetStub(), rootObject)
	if err != nil {
		return roots, err
	}
	defer iterator.Close()
	for iterator.HasNext() && len(roots) < maxListItems {
		entry, err := iterator.Next()
		if err != nil {
			return roots, err
		}
		var root Root
		if err := unmarshalState(entry.Value, &root); err != nil {
			return roots, fmt.Errorf("decode root state: %w", err)
		}
		if root.ValidUntil > now {
			roots = append(roots, root)
		}
	}
	return roots, nil
}
