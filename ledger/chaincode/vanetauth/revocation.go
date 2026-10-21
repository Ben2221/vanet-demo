package main

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func (c *VanetAuth) ReportMisbehaviour(ctx contractapi.TransactionContextInterface, pid, evidenceHash, attackType string) (ReportResult, error) {
	caller, err := requireRole(ctx, roleRSU)
	if err != nil {
		return ReportResult{}, err
	}
	if err := validateHex64("pid", pid); err != nil {
		return ReportResult{}, err
	}
	if err := validateHex64("evidenceHash", evidenceHash); err != nil {
		return ReportResult{}, err
	}
	if attackType != "" {
		if err := validateName("attackType", attackType); err != nil {
			return ReportResult{}, err
		}
	}

	revocation, revoked, err := readRevocation(ctx.GetStub(), pid)
	if err != nil {
		return ReportResult{}, err
	}
	configuration, err := c.GetConfig(ctx)
	if err != nil {
		return ReportResult{}, err
	}
	if revoked {
		return ReportResult{
			PID:            pid,
			ReportCount:    len(revocation.Reporters),
			K:              configuration.K,
			Revoked:        true,
			AlreadyRevoked: true,
		}, nil
	}

	key, err := reportKey(ctx.GetStub(), pid, caller.ID)
	if err != nil {
		return ReportResult{}, err
	}
	existing, err := ctx.GetStub().GetState(key)
	if err != nil {
		return ReportResult{}, err
	}
	if len(existing) != 0 {
		reports, err := listReports(ctx.GetStub(), pid)
		if err != nil {
			return ReportResult{}, err
		}
		return ReportResult{
			PID:         pid,
			ReportCount: len(reports),
			K:           configuration.K,
			Duplicate:   true,
		}, nil
	}

	now, err := nowMs(ctx)
	if err != nil {
		return ReportResult{}, err
	}

	report := MisbehaviourReport{
		PID:          pid,
		RSUID:        caller.ID,
		EvidenceHash: evidenceHash,
		AttackType:   attackType,
		Ts:           now,
	}
	encodedReport, err := marshalState(report)
	if err != nil {
		return ReportResult{}, err
	}
	if err := ctx.GetStub().PutState(key, encodedReport); err != nil {
		return ReportResult{}, err
	}

	// A range query omits writes from this proposal; filter the caller as well
	// to keep this count correct with mocks that expose pending writes.
	reports, err := listReports(ctx.GetStub(), pid)
	if err != nil {
		return ReportResult{}, err
	}
	reportCount, reporters, firstReportTs := summarizeReports(reports, caller.ID, now)

	// weights default to full (1000 each), so this is reportCount >= K unless the TA
	// lowered an RSU's weight (weights.go)
	weight, err := weightSum(ctx.GetStub(), reporters)
	if err != nil {
		return ReportResult{}, err
	}
	newlyRevoked := weight >= configuration.K*fullWeight
	if newlyRevoked {
		revKey, err := revocationKey(ctx.GetStub(), pid)
		if err != nil {
			return ReportResult{}, err
		}
		reason := attackType
		if reason == "" {
			reason = "AUTO_REPORTS"
		}
		revocation := Revocation{
			PID:           pid,
			Reason:        reason,
			Reporters:     reporters,
			FirstReportTs: firstReportTs,
			RevokedTs:     now,
			Source:        "AUTO_REPORTS",
		}
		encodedRevocation, err := marshalState(revocation)
		if err != nil {
			return ReportResult{}, err
		}
		if err := ctx.GetStub().PutState(revKey, encodedRevocation); err != nil {
			return ReportResult{}, err
		}
		event, err := json.Marshal(struct {
			PID       string `json:"pid"`
			RevokedTs int64  `json:"revokedTs"`
		}{PID: pid, RevokedTs: now})
		if err != nil {
			return ReportResult{}, err
		}
		if err := ctx.GetStub().SetEvent("PseudonymRevoked", event); err != nil {
			return ReportResult{}, err
		}
	}

	return ReportResult{
		PID:          pid,
		ReportCount:  reportCount,
		K:            configuration.K,
		Revoked:      newlyRevoked,
		NewlyRevoked: newlyRevoked,
	}, nil
}

func (c *VanetAuth) IsRevoked(ctx contractapi.TransactionContextInterface, pid string) (bool, error) {
	if err := validateHex64("pid", pid); err != nil {
		return false, err
	}
	return isPidRevoked(ctx.GetStub(), pid)
}

func (c *VanetAuth) ListRevokedSince(ctx contractapi.TransactionContextInterface, sinceMs string) ([]Revocation, error) {
	revocations := emptyRevocationList()
	since, err := parseSinceMs(sinceMs)
	if err != nil {
		return revocations, err
	}
	iterator, err := partialCompositeKey(ctx.GetStub(), revObject)
	if err != nil {
		return revocations, err
	}
	defer iterator.Close()

	for iterator.HasNext() && len(revocations) < maxListItems {
		entry, err := iterator.Next()
		if err != nil {
			return revocations, err
		}
		var revocation Revocation
		if err := unmarshalState(entry.Value, &revocation); err != nil {
			return revocations, fmt.Errorf("decode revocation state: %w", err)
		}
		if revocation.RevokedTs < since {
			continue
		}
		if revocation.Reporters == nil {
			revocation.Reporters = emptyStringList()
		}
		revocations = append(revocations, revocation)
	}
	return revocations, nil
}

func (c *VanetAuth) GetPseudonymStatus(ctx contractapi.TransactionContextInterface, pid string) (PseudonymStatus, error) {
	status := newPseudonymStatus(pid)
	if err := validateHex64("pid", pid); err != nil {
		return status, err
	}
	now, err := nowMs(ctx)
	if err != nil {
		return status, err
	}

	revocation, revoked, err := readRevocation(ctx.GetStub(), pid)
	if err != nil {
		return status, err
	}
	status.Revoked = revoked
	if revoked {
		status.RevokedTs = revocation.RevokedTs
		status.FirstReportTs = revocation.FirstReportTs
		status.Reporters = append(emptyStringList(), revocation.Reporters...)
	}

	reports, err := listReports(ctx.GetStub(), pid)
	if err != nil {
		return status, err
	}
	status.ReportCount = len(reports)
	if len(reports) != 0 {
		reporters := emptyStringList()
		firstReportTs := reports[0].Ts
		for _, report := range reports {
			reporters = append(reporters, report.RSUID)
			if report.Ts < firstReportTs {
				firstReportTs = report.Ts
			}
		}
		sort.Strings(reporters)
		status.Reporters = reporters
		if status.FirstReportTs == 0 || firstReportTs < status.FirstReportTs {
			status.FirstReportTs = firstReportTs
		}
	}

	auth, hasAuth, err := readAuth(ctx.GetStub(), pid)
	if err != nil {
		return status, err
	}
	if hasAuth && auth.Expiry > now && !revoked {
		status.ActiveAuth = auth
	}
	return status, nil
}

func isPidRevoked(stub shim.ChaincodeStubInterface, pid string) (bool, error) {
	key, err := revocationKey(stub, pid)
	if err != nil {
		return false, err
	}
	value, err := stub.GetState(key)
	if err != nil {
		return false, err
	}
	return len(value) != 0, nil
}

func readRevocation(stub shim.ChaincodeStubInterface, pid string) (Revocation, bool, error) {
	key, err := revocationKey(stub, pid)
	if err != nil {
		return emptyRevocation(), false, err
	}
	encoded, err := stub.GetState(key)
	if err != nil {
		return emptyRevocation(), false, err
	}
	if len(encoded) == 0 {
		return emptyRevocation(), false, nil
	}
	var revocation Revocation
	if err := unmarshalState(encoded, &revocation); err != nil {
		return emptyRevocation(), false, err
	}
	if revocation.Reporters == nil {
		revocation.Reporters = emptyStringList()
	}
	return revocation, true, nil
}

func summarizeReports(reports []MisbehaviourReport, reportingRSU string, now int64) (int, []string, int64) {
	reporters := emptyStringList()
	firstReportTs := now
	count := 1
	for _, report := range reports {
		if report.RSUID == reportingRSU {
			continue
		}
		count++
		reporters = append(reporters, report.RSUID)
		if report.Ts < firstReportTs {
			firstReportTs = report.Ts
		}
	}
	reporters = append(reporters, reportingRSU)
	sort.Strings(reporters)
	return count, reporters, firstReportTs
}

func listReports(stub shim.ChaincodeStubInterface, pid string) ([]MisbehaviourReport, error) {
	reports := make([]MisbehaviourReport, 0)
	iterator, err := partialCompositeKey(stub, reportObject, pid)
	if err != nil {
		return reports, err
	}
	defer iterator.Close()

	for iterator.HasNext() {
		entry, err := iterator.Next()
		if err != nil {
			return reports, err
		}
		var report MisbehaviourReport
		if err := unmarshalState(entry.Value, &report); err != nil {
			return reports, fmt.Errorf("decode report state: %w", err)
		}
		reports = append(reports, report)
	}
	return reports, nil
}
