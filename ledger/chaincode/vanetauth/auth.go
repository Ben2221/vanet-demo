package main

import (
	"fmt"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func (c *VanetAuth) RecordAuth(ctx contractapi.TransactionContextInterface, pid, service, vehicleClass, expiry string) (AuthRecord, error) {
	caller, err := requireRole(ctx, roleRSU)
	if err != nil {
		return AuthRecord{}, err
	}
	if err := validateHex64("pid", pid); err != nil {
		return AuthRecord{}, err
	}
	if err := validateName("service", service); err != nil {
		return AuthRecord{}, err
	}
	if err := validateName("class", vehicleClass); err != nil {
		return AuthRecord{}, err
	}
	expiryValue, err := parseIntArg("expiry", expiry)
	if err != nil {
		return AuthRecord{}, err
	}

	revoked, err := isPidRevoked(ctx.GetStub(), pid)
	if err != nil {
		return AuthRecord{}, err
	}
	if revoked {
		return AuthRecord{}, errf("ERR_CONFLICT", "pseudonym revoked")
	}

	policy, found, err := readPolicy(ctx.GetStub(), service)
	if err != nil {
		return AuthRecord{}, err
	}
	if !found {
		return AuthRecord{}, errf("ERR_NOT_FOUND", "policy for service %q was not found", service)
	}
	if !containsString(policy.Classes, vehicleClass) {
		return AuthRecord{}, errf("ERR_FORBIDDEN", "class not allowed for service")
	}

	now, err := nowMs(ctx)
	if err != nil {
		return AuthRecord{}, err
	}
	configuration, err := c.GetConfig(ctx)
	if err != nil {
		return AuthRecord{}, err
	}
	maxExpiry := now + int64(configuration.MaxAuthTtlSec)*1000
	if expiryValue <= now || expiryValue > maxExpiry {
		return AuthRecord{}, errf("ERR_BAD_INPUT", "expiry must be in the future and within maxAuthTtlSec")
	}

	key, err := authKey(ctx.GetStub(), pid)
	if err != nil {
		return AuthRecord{}, err
	}
	existingBytes, err := ctx.GetStub().GetState(key)
	if err != nil {
		return AuthRecord{}, err
	}

	record := AuthRecord{
		PID:          pid,
		Service:      service,
		Class:        vehicleClass,
		Expiry:       expiryValue,
		RSUID:        caller.ID,
		FirstTs:      now,
		Ts:           now,
		SessionCount: 1,
	}
	if len(existingBytes) != 0 {
		if err := unmarshalState(existingBytes, &record); err != nil {
			return AuthRecord{}, err
		}
		record.Service = service
		record.Class = vehicleClass
		record.Expiry = expiryValue
		record.RSUID = caller.ID
		record.Ts = now
		record.SessionCount++
	}

	encoded, err := marshalState(record)
	if err != nil {
		return AuthRecord{}, err
	}
	if err := ctx.GetStub().PutState(key, encoded); err != nil {
		return AuthRecord{}, err
	}
	return record, nil
}

func (c *VanetAuth) GetAuth(ctx contractapi.TransactionContextInterface, pid string) (AuthRecord, error) {
	if err := validateHex64("pid", pid); err != nil {
		return AuthRecord{}, err
	}
	now, err := nowMs(ctx)
	if err != nil {
		return AuthRecord{}, err
	}
	record, found, err := readAuth(ctx.GetStub(), pid)
	if err != nil {
		return AuthRecord{}, err
	}
	if !found || record.Expiry <= now {
		return AuthRecord{}, errf("ERR_NOT_FOUND", "active authorization for pid %q was not found", pid)
	}
	revoked, err := isPidRevoked(ctx.GetStub(), pid)
	if err != nil {
		return AuthRecord{}, err
	}
	if revoked {
		return AuthRecord{}, errf("ERR_NOT_FOUND", "active authorization for pid %q was not found", pid)
	}
	return record, nil
}

func (c *VanetAuth) ListAuthsSince(ctx contractapi.TransactionContextInterface, sinceMs string) ([]AuthRecord, error) {
	auths := emptyAuthList()
	since, err := parseSinceMs(sinceMs)
	if err != nil {
		return auths, err
	}
	now, err := nowMs(ctx)
	if err != nil {
		return auths, err
	}
	iterator, err := partialCompositeKey(ctx.GetStub(), authObject)
	if err != nil {
		return auths, err
	}
	defer iterator.Close()

	for iterator.HasNext() && len(auths) < maxListItems {
		entry, err := iterator.Next()
		if err != nil {
			return auths, err
		}
		var record AuthRecord
		if err := unmarshalState(entry.Value, &record); err != nil {
			return auths, fmt.Errorf("decode authorization state: %w", err)
		}
		if record.Ts < since || record.Expiry <= now {
			continue
		}
		revoked, err := isPidRevoked(ctx.GetStub(), record.PID)
		if err != nil {
			return auths, err
		}
		if !revoked {
			auths = append(auths, record)
		}
	}
	return auths, nil
}

func (c *VanetAuth) CheckAccess(ctx contractapi.TransactionContextInterface, pid, vehicleClass, service string) (CheckAccessResult, error) {
	result := newCheckAccessResult()
	if err := validateHex64("pid", pid); err != nil {
		return result, err
	}
	if err := validateName("class", vehicleClass); err != nil {
		return result, err
	}
	if err := validateName("service", service); err != nil {
		return result, err
	}
	now, err := nowMs(ctx)
	if err != nil {
		return result, err
	}

	revoked, err := isPidRevoked(ctx.GetStub(), pid)
	if err != nil {
		return result, err
	}
	if revoked {
		result.Reasons = append(result.Reasons, "REVOKED")
	}

	policy, hasPolicy, err := readPolicy(ctx.GetStub(), service)
	if err != nil {
		return result, err
	}
	classAllowed := false
	if !hasPolicy {
		result.Reasons = append(result.Reasons, "NO_POLICY")
	} else {
		classAllowed = containsString(policy.Classes, vehicleClass)
		if !classAllowed {
			result.Reasons = append(result.Reasons, "CLASS_NOT_ALLOWED")
		}
	}

	auth, hasAuth, err := readAuth(ctx.GetStub(), pid)
	if err != nil {
		return result, err
	}
	if hasAuth && auth.Expiry > now && !revoked {
		result.ActiveAuth = auth
	} else {
		result.Reasons = append(result.Reasons, "NO_ACTIVE_AUTH")
	}

	result.Allow = !revoked && hasPolicy && classAllowed
	return result, nil
}

func readAuth(stub shim.ChaincodeStubInterface, pid string) (AuthRecord, bool, error) {
	key, err := authKey(stub, pid)
	if err != nil {
		return AuthRecord{}, false, err
	}
	encoded, err := stub.GetState(key)
	if err != nil {
		return AuthRecord{}, false, err
	}
	if len(encoded) == 0 {
		return AuthRecord{}, false, nil
	}
	var record AuthRecord
	if err := unmarshalState(encoded, &record); err != nil {
		return AuthRecord{}, false, err
	}
	return record, true, nil
}

func readPolicy(stub shim.ChaincodeStubInterface, service string) (Policy, bool, error) {
	key, err := policyKey(stub, service)
	if err != nil {
		return emptyPolicy(), false, err
	}
	encoded, err := stub.GetState(key)
	if err != nil {
		return emptyPolicy(), false, err
	}
	if len(encoded) == 0 {
		return emptyPolicy(), false, nil
	}
	var policy Policy
	if err := unmarshalState(encoded, &policy); err != nil {
		return emptyPolicy(), false, err
	}
	if policy.Classes == nil {
		policy.Classes = make([]string, 0)
	}
	return policy, true, nil
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
