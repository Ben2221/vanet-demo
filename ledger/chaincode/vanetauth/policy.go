package main

import (
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func emptyPolicy() Policy {
	return Policy{Classes: []string{}}
}

func (c *VanetAuth) SetPolicy(ctx contractapi.TransactionContextInterface, service, classesJSON string) (Policy, error) {
	if _, err := requireRole(ctx, roleTA); err != nil {
		return emptyPolicy(), err
	}
	if err := validateName("service", service); err != nil {
		return emptyPolicy(), err
	}
	classes, err := parseStringArray("classes", classesJSON)
	if err != nil {
		return emptyPolicy(), err
	}
	now, err := nowMs(ctx)
	if err != nil {
		return emptyPolicy(), err
	}
	key, err := policyKey(ctx.GetStub(), service)
	if err != nil {
		return emptyPolicy(), err
	}
	policy := Policy{Service: service, Classes: uniqueStrings(classes), UpdatedTs: now}
	encoded, err := marshalState(policy)
	if err != nil {
		return emptyPolicy(), err
	}
	if err := ctx.GetStub().PutState(key, encoded); err != nil {
		return emptyPolicy(), err
	}
	return policy, nil
}

func (c *VanetAuth) GetPolicy(ctx contractapi.TransactionContextInterface, service string) (Policy, error) {
	if err := validateName("service", service); err != nil {
		return emptyPolicy(), err
	}
	key, err := policyKey(ctx.GetStub(), service)
	if err != nil {
		return emptyPolicy(), err
	}
	encoded, err := ctx.GetStub().GetState(key)
	if err != nil {
		return emptyPolicy(), err
	}
	if len(encoded) == 0 {
		return emptyPolicy(), errf("ERR_NOT_FOUND", "policy for service %q was not found", service)
	}
	var policy Policy
	if err := unmarshalState(encoded, &policy); err != nil {
		return emptyPolicy(), err
	}
	if policy.Classes == nil {
		policy.Classes = make([]string, 0)
	}
	return policy, nil
}

func (c *VanetAuth) ListPolicies(ctx contractapi.TransactionContextInterface) ([]Policy, error) {
	policies := make([]Policy, 0)
	iterator, err := partialCompositeKey(ctx.GetStub(), policyObject)
	if err != nil {
		return policies, err
	}
	defer iterator.Close()

	for iterator.HasNext() && len(policies) < maxListItems {
		entry, err := iterator.Next()
		if err != nil {
			return policies, err
		}
		var policy Policy
		if err := unmarshalState(entry.Value, &policy); err != nil {
			return policies, fmt.Errorf("decode policy state: %w", err)
		}
		if policy.Classes == nil {
			policy.Classes = make([]string, 0)
		}
		policies = append(policies, policy)
	}
	return policies, nil
}
