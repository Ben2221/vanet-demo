package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

var (
	reHex64 = regexp.MustCompile(`^[a-f0-9]{64}$`)
	reName  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	reReqID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
)

func errf(code, format string, args ...interface{}) error {
	return fmt.Errorf("%s: %s", code, fmt.Sprintf(format, args...))
}

func getCaller(ctx contractapi.TransactionContextInterface) (Caller, error) {
	identity := ctx.GetClientIdentity()
	msp, err := identity.GetMSPID()
	if err != nil {
		return Caller{}, err
	}
	certificate, err := identity.GetX509Certificate()
	if err != nil {
		return Caller{}, err
	}
	caller := Caller{MSP: msp, ID: certificate.Subject.CommonName, Role: roleUnknown}
	switch msp {
	case mspTA:
		caller.Role = roleTA
	case mspRSU:
		caller.Role = roleRSU
	}
	if caller.ID == "" {
		return Caller{}, errf("ERR_FORBIDDEN", "caller certificate has no CommonName")
	}
	return caller, nil
}

func requireRole(ctx contractapi.TransactionContextInterface, roles ...string) (Caller, error) {
	caller, err := getCaller(ctx)
	if err != nil {
		return caller, err
	}
	for _, role := range roles {
		if caller.Role == role {
			return caller, nil
		}
	}
	return caller, errf("ERR_FORBIDDEN", "%s (%s) may not call this function", caller.ID, caller.Role)
}

func nowMs(ctx contractapi.TransactionContextInterface) (int64, error) {
	timestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return 0, err
	}
	if timestamp == nil {
		return 0, fmt.Errorf("transaction timestamp is unavailable")
	}
	return timestampMs(timestamp.Seconds, timestamp.Nanos), nil
}

func timestampMs(seconds int64, nanos int32) int64 {
	return seconds*1000 + int64(nanos)/1_000_000
}

func validateSafeString(field, value string) error {
	for _, character := range value {
		if character == '\x00' || character == '\U0010FFFF' {
			return errf("ERR_BAD_INPUT", "%s contains a reserved character", field)
		}
	}
	return nil
}

func validateName(field, value string) error {
	if err := validateSafeString(field, value); err != nil {
		return err
	}
	if !reName.MatchString(value) {
		return errf("ERR_BAD_INPUT", "%s must match %s", field, reName.String())
	}
	return nil
}

func validateHex64(field, value string) error {
	if err := validateSafeString(field, value); err != nil {
		return err
	}
	if !reHex64.MatchString(value) {
		return errf("ERR_BAD_INPUT", "%s must be 64 lowercase hexadecimal characters", field)
	}
	return nil
}

func validateReqID(value string) error {
	if err := validateSafeString("reqId", value); err != nil {
		return err
	}
	if !reReqID.MatchString(value) {
		return errf("ERR_BAD_INPUT", "reqId must match %s", reReqID.String())
	}
	return nil
}

func validateFreeText(field, value string) error {
	if err := validateSafeString(field, value); err != nil {
		return err
	}
	if len([]rune(value)) > 128 {
		return errf("ERR_BAD_INPUT", "%s must be at most 128 characters", field)
	}
	return nil
}

func parseIntArg(field, value string) (int64, error) {
	if err := validateSafeString(field, value); err != nil {
		return 0, err
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, errf("ERR_BAD_INPUT", "%s must be an integer", field)
	}
	return parsed, nil
}

func parseSinceMs(value string) (int64, error) {
	parsed, err := parseIntArg("sinceMs", value)
	if err != nil {
		return 0, err
	}
	if parsed < 0 {
		return 0, errf("ERR_BAD_INPUT", "sinceMs must be non-negative")
	}
	return parsed, nil
}

func rootAttribute(epoch int64) (string, error) {
	if epoch < 0 {
		return "", errf("ERR_BAD_INPUT", "epoch must be non-negative")
	}
	return fmt.Sprintf("%010d", epoch), nil
}

func rootKey(stub shim.ChaincodeStubInterface, epoch int64) (string, error) {
	attribute, err := rootAttribute(epoch)
	if err != nil {
		return "", err
	}
	return createCompositeKey(stub, rootObject, attribute)
}

func policyKey(stub shim.ChaincodeStubInterface, service string) (string, error) {
	if err := validateName("service", service); err != nil {
		return "", err
	}
	return createCompositeKey(stub, policyObject, service)
}

func authKey(stub shim.ChaincodeStubInterface, pid string) (string, error) {
	if err := validateHex64("pid", pid); err != nil {
		return "", err
	}
	return createCompositeKey(stub, authObject, pid)
}

func reportKey(stub shim.ChaincodeStubInterface, pid, rsuID string) (string, error) {
	if err := validateHex64("pid", pid); err != nil {
		return "", err
	}
	if err := validateSafeString("rsuId", rsuID); err != nil {
		return "", err
	}
	if rsuID == "" {
		return "", errf("ERR_BAD_INPUT", "rsuId must not be empty")
	}
	return createCompositeKey(stub, reportObject, pid, rsuID)
}

func revocationKey(stub shim.ChaincodeStubInterface, pid string) (string, error) {
	if err := validateHex64("pid", pid); err != nil {
		return "", err
	}
	return createCompositeKey(stub, revObject, pid)
}

func emptyAuthList() []AuthRecord {
	return make([]AuthRecord, 0)
}

func emptyRevocationList() []Revocation {
	return make([]Revocation, 0)
}

func emptyStringList() []string {
	return make([]string, 0)
}

func newCheckAccessResult() CheckAccessResult {
	return CheckAccessResult{Reasons: emptyStringList()}
}

func newPseudonymStatus(pid string) PseudonymStatus {
	return PseudonymStatus{PID: pid, Reporters: emptyStringList()}
}

func emptyRevocation() Revocation {
	return Revocation{Reporters: emptyStringList()}
}

func createCompositeKey(stub shim.ChaincodeStubInterface, objectType string, attributes ...string) (string, error) {
	for _, attribute := range attributes {
		if err := validateSafeString("composite key attribute", attribute); err != nil {
			return "", err
		}
	}
	key, err := stub.CreateCompositeKey(objectType, attributes)
	if err != nil {
		return "", errf("ERR_BAD_INPUT", "invalid composite key: %v", err)
	}
	return key, nil
}

func marshalState(value interface{}) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal ledger state: %w", err)
	}
	return encoded, nil
}

func unmarshalState(value []byte, target interface{}) error {
	if err := json.Unmarshal(value, target); err != nil {
		return fmt.Errorf("decode ledger state: %w", err)
	}
	return nil
}

func parseStringArray(field, encoded string) ([]string, error) {
	if err := validateSafeString(field, encoded); err != nil {
		return nil, err
	}
	var values []string
	if err := json.Unmarshal([]byte(encoded), &values); err != nil || values == nil {
		return nil, errf("ERR_BAD_INPUT", "%s must be a JSON array of strings", field)
	}
	for _, value := range values {
		if err := validateName("class", value); err != nil {
			return nil, err
		}
	}
	return values, nil
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	unique := make([]string, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		unique = append(unique, value)
	}
	return unique
}

func partialCompositeKey(stub shim.ChaincodeStubInterface, objectType string, attributes ...string) (shim.StateQueryIteratorInterface, error) {
	for _, attribute := range attributes {
		if err := validateSafeString("composite key attribute", attribute); err != nil {
			return nil, err
		}
	}
	iterator, err := stub.GetStateByPartialCompositeKey(objectType, attributes)
	if err != nil {
		return nil, err
	}
	return iterator, nil
}
