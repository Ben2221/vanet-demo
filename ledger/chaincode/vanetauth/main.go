package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type VanetAuth struct {
	contractapi.Contract
}

// WhoAmI reports the caller's MSP, derived role and a short ID hash.
func (c *VanetAuth) WhoAmI(ctx contractapi.TransactionContextInterface) (string, error) {
	msp, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return "", err
	}
	id, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return "", err
	}

	role := "UNKNOWN"
	switch msp {
	case "Org1MSP":
		role = "TA"
	case "Org2MSP":
		role = "RSU"
	}

	hash := sha256.Sum256([]byte(id))
	return fmt.Sprintf("msp=%s role=%s caller=%s", msp, role, hex.EncodeToString(hash[:4])), nil
}

// Put and Get are temporary helpers for exercising ledger reads and writes.
func (c *VanetAuth) Put(ctx contractapi.TransactionContextInterface, key, value string) error {
	return ctx.GetStub().PutState(key, []byte(value))
}

func (c *VanetAuth) Get(ctx contractapi.TransactionContextInterface, key string) (string, error) {
	value, err := ctx.GetStub().GetState(key)
	if err != nil {
		return "", err
	}
	return string(value), nil
}

func main() {
	chaincode, err := contractapi.NewChaincode(&VanetAuth{})
	if err != nil {
		log.Panicf("create chaincode: %v", err)
	}
	if err := chaincode.Start(); err != nil {
		log.Panicf("start chaincode: %v", err)
	}
}
