package main

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func (c *VanetAuth) RequestTrace(ctx contractapi.TransactionContextInterface, reqID, pid, reason string) (TraceRecord, error) {
	trace := emptyTrace(reqID)
	caller, err := requireRole(ctx, roleTA, roleRSU)
	if err != nil {
		return trace, err
	}
	if err := validateReqID(reqID); err != nil {
		return trace, err
	}
	if err := validateHex64("pid", pid); err != nil {
		return trace, err
	}
	if err := validateTraceReason(reason); err != nil {
		return trace, err
	}

	revoked, err := isPidRevoked(ctx.GetStub(), pid)
	if err != nil {
		return trace, err
	}
	if !revoked {
		return trace, errf("ERR_CONFLICT", "pseudonym must be revoked before trace request")
	}

	key, err := traceKey(ctx.GetStub(), reqID)
	if err != nil {
		return trace, err
	}
	existing, err := ctx.GetStub().GetState(key)
	if err != nil {
		return trace, err
	}
	if len(existing) != 0 {
		return trace, errf("ERR_CONFLICT", "trace request %q already exists", reqID)
	}

	configuration, err := c.GetConfig(ctx)
	if err != nil {
		return trace, err
	}
	now, err := nowMs(ctx)
	if err != nil {
		return trace, err
	}
	trace = TraceRecord{
		ReqID:       reqID,
		PID:         pid,
		Reason:      reason,
		Requester:   caller.ID,
		Status:      "PENDING",
		Threshold:   configuration.TraceThreshold,
		Approvals:   emptyStringList(),
		RevokedPids: emptyStringList(),
		CreatedTs:   now,
	}
	encoded, err := marshalState(trace)
	if err != nil {
		return emptyTrace(reqID), err
	}
	if err := ctx.GetStub().PutState(key, encoded); err != nil {
		return emptyTrace(reqID), err
	}
	return trace, nil
}

func (c *VanetAuth) ApproveTrace(ctx contractapi.TransactionContextInterface, reqID string) (TraceRecord, error) {
	trace := emptyTrace(reqID)
	caller, err := requireRole(ctx, roleRSU)
	if err != nil {
		return trace, err
	}
	if err := validateReqID(reqID); err != nil {
		return trace, err
	}
	trace, found, err := readTrace(ctx.GetStub(), reqID)
	if err != nil {
		return trace, err
	}
	if !found {
		return trace, errf("ERR_NOT_FOUND", "trace request %q was not found", reqID)
	}
	if trace.Status != "PENDING" {
		return trace, errf("ERR_CONFLICT", "trace request is not pending")
	}
	if containsString(trace.Approvals, caller.ID) {
		return trace, errf("ERR_CONFLICT", "RSU %q has already approved this trace", caller.ID)
	}

	now, err := nowMs(ctx)
	if err != nil {
		return trace, err
	}
	trace.Approvals = append(trace.Approvals, caller.ID)
	if len(trace.Approvals) >= trace.Threshold {
		trace.Status = "APPROVED"
		trace.ApprovedTs = now
	}
	if err := writeTrace(ctx.GetStub(), trace); err != nil {
		return trace, err
	}
	return trace, nil
}

func (c *VanetAuth) GetTrace(ctx contractapi.TransactionContextInterface, reqID string) (TraceRecord, error) {
	trace := emptyTrace(reqID)
	if err := validateReqID(reqID); err != nil {
		return trace, err
	}
	trace, found, err := readTrace(ctx.GetStub(), reqID)
	if err != nil {
		return trace, err
	}
	if !found {
		return trace, errf("ERR_NOT_FOUND", "trace request %q was not found", reqID)
	}
	return trace, nil
}

func (c *VanetAuth) Revoke(ctx contractapi.TransactionContextInterface, reqID, pidsJSON, reason string) (TraceRecord, error) {
	trace := emptyTrace(reqID)
	if _, err := requireRole(ctx, roleTA); err != nil {
		return trace, err
	}
	if err := validateReqID(reqID); err != nil {
		return trace, err
	}
	if err := validateTraceReason(reason); err != nil {
		return trace, err
	}
	pids, err := parseTracePIDs(pidsJSON)
	if err != nil {
		return trace, err
	}

	trace, found, err := readTrace(ctx.GetStub(), reqID)
	if err != nil {
		return trace, err
	}
	if !found {
		return trace, errf("ERR_NOT_FOUND", "trace request %q was not found", reqID)
	}
	if trace.Status != "APPROVED" {
		return trace, errf("ERR_CONFLICT", "trace request must be approved before revocation")
	}
	if !containsString(pids, trace.PID) {
		return trace, errf("ERR_BAD_INPUT", "pids must include the traced pid")
	}

	now, err := nowMs(ctx)
	if err != nil {
		return trace, err
	}
	uniquePids := uniqueStrings(pids)
	for _, pid := range uniquePids {
		revoked, err := isPidRevoked(ctx.GetStub(), pid)
		if err != nil {
			return trace, err
		}
		if revoked {
			continue
		}
		revocation := Revocation{
			PID:           pid,
			Reason:        reason,
			Reporters:     emptyStringList(),
			FirstReportTs: 0,
			RevokedTs:     now,
			Source:        "TRACE",
			ReqID:         reqID,
		}
		encoded, err := marshalState(revocation)
		if err != nil {
			return trace, err
		}
		key, err := revocationKey(ctx.GetStub(), pid)
		if err != nil {
			return trace, err
		}
		if err := ctx.GetStub().PutState(key, encoded); err != nil {
			return trace, err
		}
	}

	trace.Status = "EXECUTED"
	trace.RevokedPids = append(emptyStringList(), uniquePids...)
	trace.ExecutedTs = now
	if err := writeTrace(ctx.GetStub(), trace); err != nil {
		return trace, err
	}
	return trace, nil
}

func traceKey(stub shim.ChaincodeStubInterface, reqID string) (string, error) {
	if err := validateReqID(reqID); err != nil {
		return "", err
	}
	return createCompositeKey(stub, traceObject, reqID)
}

func emptyTrace(reqID string) TraceRecord {
	return TraceRecord{ReqID: reqID, Approvals: emptyStringList(), RevokedPids: emptyStringList()}
}

func readTrace(stub shim.ChaincodeStubInterface, reqID string) (TraceRecord, bool, error) {
	key, err := traceKey(stub, reqID)
	if err != nil {
		return emptyTrace(reqID), false, err
	}
	encoded, err := stub.GetState(key)
	if err != nil {
		return emptyTrace(reqID), false, err
	}
	if len(encoded) == 0 {
		return emptyTrace(reqID), false, nil
	}
	var trace TraceRecord
	if err := unmarshalState(encoded, &trace); err != nil {
		return emptyTrace(reqID), false, fmt.Errorf("decode trace state: %w", err)
	}
	if trace.Approvals == nil {
		trace.Approvals = emptyStringList()
	}
	if trace.RevokedPids == nil {
		trace.RevokedPids = emptyStringList()
	}
	return trace, true, nil
}

func writeTrace(stub shim.ChaincodeStubInterface, trace TraceRecord) error {
	if trace.Approvals == nil {
		trace.Approvals = emptyStringList()
	}
	if trace.RevokedPids == nil {
		trace.RevokedPids = emptyStringList()
	}
	key, err := traceKey(stub, trace.ReqID)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(trace)
	if err != nil {
		return fmt.Errorf("marshal trace state: %w", err)
	}
	return stub.PutState(key, encoded)
}

func validateTraceReason(reason string) error {
	if reason == "" {
		return errf("ERR_BAD_INPUT", "reason must not be empty")
	}
	return validateFreeText("reason", reason)
}

func parseTracePIDs(encoded string) ([]string, error) {
	if err := validateSafeString("pids", encoded); err != nil {
		return emptyStringList(), err
	}
	var pids []string
	if err := json.Unmarshal([]byte(encoded), &pids); err != nil || pids == nil {
		return emptyStringList(), errf("ERR_BAD_INPUT", "pids must be a JSON array of pseudonyms")
	}
	if len(pids) > 200 {
		return emptyStringList(), errf("ERR_BAD_INPUT", "pids may contain at most 200 pseudonyms")
	}
	for _, pid := range pids {
		if err := validateHex64("pid", pid); err != nil {
			return emptyStringList(), err
		}
	}
	return pids, nil
}
