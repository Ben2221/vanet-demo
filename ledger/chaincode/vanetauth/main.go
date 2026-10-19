package main

import (
	"log"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type VanetAuth struct {
	contractapi.Contract
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
