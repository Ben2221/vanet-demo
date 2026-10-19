package main

import "github.com/hyperledger/fabric-contract-api-go/contractapi"

func (c *VanetAuth) WhoAmI(ctx contractapi.TransactionContextInterface) (WhoAmIResult, error) {
	caller, err := getCaller(ctx)
	if err != nil {
		return WhoAmIResult{}, err
	}
	return WhoAmIResult{MSP: caller.MSP, Role: caller.Role, ID: caller.ID}, nil
}
