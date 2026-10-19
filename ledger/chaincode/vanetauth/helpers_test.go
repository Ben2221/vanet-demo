package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hyperledger/fabric-chaincode-go/shimtest"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func TestContractAPIDefinitionIsValid(t *testing.T) {
	if _, err := contractapi.NewChaincode(&VanetAuth{}); err != nil {
		t.Fatalf("create contract API chaincode: %v", err)
	}
}

func TestValidators(t *testing.T) {
	validHash := strings.Repeat("a", 64)
	if err := validateHex64("pid", validHash); err != nil {
		t.Fatalf("valid lowercase hex rejected: %v", err)
	}
	if err := validateHex64("pid", strings.Repeat("A", 64)); err == nil {
		t.Fatal("uppercase hex accepted")
	}
	if err := validateName("service", "emergency-priority"); err != nil {
		t.Fatalf("valid name rejected: %v", err)
	}
	if err := validateName("service", "Emergency"); err == nil {
		t.Fatal("uppercase name accepted")
	}
	if err := validateReqID("trace_1-abc"); err != nil {
		t.Fatalf("valid request ID rejected: %v", err)
	}
	if err := validateReqID("trace/id"); err == nil {
		t.Fatal("invalid request ID accepted")
	}
}

func TestRejectReservedCompositeKeyCharacters(t *testing.T) {
	for _, value := range []string{"left\x00right", "left\U0010FFFFright"} {
		if err := validateSafeString("key", value); err == nil {
			t.Fatalf("reserved character accepted in %q", value)
		}
	}
}

func TestCompositeKeyBuilders(t *testing.T) {
	stub := shimtest.NewMockStub("test", nil)
	root, err := rootKey(stub, 7)
	if err != nil {
		t.Fatalf("root key: %v", err)
	}
	if want := "\x00root\x000000000007\x00"; root != want {
		t.Fatalf("root key = %q, want %q", root, want)
	}
	policy, err := policyKey(stub, "toll")
	if err != nil {
		t.Fatalf("policy key: %v", err)
	}
	if want := "\x00policy\x00toll\x00"; policy != want {
		t.Fatalf("policy key = %q, want %q", policy, want)
	}
}

func TestStageBCompositeKeyBuilders(t *testing.T) {
	stub := shimtest.NewMockStub("test", nil)
	pid := strings.Repeat("a", 64)
	cases := []struct {
		name string
		key  func() (string, error)
		want string
	}{
		{"auth", func() (string, error) { return authKey(stub, pid) }, "\x00auth\x00" + pid + "\x00"},
		{"report", func() (string, error) { return reportKey(stub, pid, "rsu1") }, "\x00rep\x00" + pid + "\x00rsu1\x00"},
		{"revocation", func() (string, error) { return revocationKey(stub, pid) }, "\x00rev\x00" + pid + "\x00"},
		{"trace", func() (string, error) { return traceKey(stub, "trace-1") }, "\x00trace\x00trace-1\x00"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got, err := test.key()
			if err != nil {
				t.Fatalf("key builder: %v", err)
			}
			if got != test.want {
				t.Fatalf("key = %q, want %q", got, test.want)
			}
		})
	}
}

func TestReportResultSerializesExactVariants(t *testing.T) {
	cases := []struct {
		name  string
		value ReportResult
		want  string
	}{
		{"already revoked", ReportResult{PID: "pid", ReportCount: 2, K: 2, Revoked: true, AlreadyRevoked: true}, `{"pid":"pid","reportCount":2,"K":2,"revoked":true,"newlyRevoked":false,"duplicate":false,"alreadyRevoked":true}`},
		{"duplicate", ReportResult{PID: "pid", ReportCount: 1, K: 2, Duplicate: true}, `{"pid":"pid","reportCount":1,"K":2,"revoked":false,"newlyRevoked":false,"duplicate":true,"alreadyRevoked":false}`},
		{"new report", ReportResult{PID: "pid", ReportCount: 2, K: 2, Revoked: true, NewlyRevoked: true}, `{"pid":"pid","reportCount":2,"K":2,"revoked":true,"newlyRevoked":true,"duplicate":false,"alreadyRevoked":false}`},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := json.Marshal(test.value)
			if err != nil {
				t.Fatalf("marshal report result: %v", err)
			}
			if string(encoded) != test.want {
				t.Fatalf("serialized result = %s, want %s", encoded, test.want)
			}
		})
	}
}

func TestReportSummaryCountsExistingPlusCurrentOnce(t *testing.T) {
	pid := strings.Repeat("a", 64)
	count, reporters, firstTs := summarizeReports([]MisbehaviourReport{
		{PID: pid, RSUID: "rsu1", Ts: 100},
		{PID: pid, RSUID: "rsu2", Ts: 200}, // visible in mocks as the pending current write
	}, "rsu2", 200)
	if count != 2 {
		t.Fatalf("report count = %d, want 2", count)
	}
	if firstTs != 100 {
		t.Fatalf("first report timestamp = %d, want 100", firstTs)
	}
	if len(reporters) != 2 || reporters[0] != "rsu1" || reporters[1] != "rsu2" {
		t.Fatalf("reporters = %v, want [rsu1 rsu2]", reporters)
	}
}

func TestParseSinceMs(t *testing.T) {
	if got, err := parseSinceMs("123"); err != nil || got != 123 {
		t.Fatalf("parseSinceMs(123) = %d, %v", got, err)
	}
	for _, value := range []string{"-1", "not-a-number"} {
		if _, err := parseSinceMs(value); err == nil {
			t.Errorf("parseSinceMs(%q) accepted invalid input", value)
		}
	}
}

func TestStageBEmptyArrayFieldsAreNonNil(t *testing.T) {
	if emptyAuthList() == nil {
		t.Fatal("empty auth list is nil")
	}
	if emptyRevocationList() == nil {
		t.Fatal("empty revocation list is nil")
	}
	if emptyStringList() == nil {
		t.Fatal("empty string list is nil")
	}
	if newCheckAccessResult().Reasons == nil {
		t.Fatal("CheckAccess reasons are nil")
	}
	if newPseudonymStatus("pid").Reporters == nil {
		t.Fatal("pseudonym status reporters are nil")
	}
	if emptyRevocation().Reporters == nil {
		t.Fatal("revocation reporters are nil")
	}

	encoded, err := json.Marshal(struct {
		Auths     []AuthRecord      `json:"auths"`
		Revoked   []Revocation      `json:"revoked"`
		Check     CheckAccessResult `json:"check"`
		Pseudonym PseudonymStatus   `json:"pseudonym"`
	}{
		Auths:     emptyAuthList(),
		Revoked:   emptyRevocationList(),
		Check:     newCheckAccessResult(),
		Pseudonym: newPseudonymStatus("pid"),
	})
	if err != nil {
		t.Fatalf("marshal empty collection results: %v", err)
	}
	for _, field := range []string{`"auths":[]`, `"revoked":[]`, `"reasons":[]`, `"reporters":[]`} {
		if !strings.Contains(string(encoded), field) {
			t.Errorf("serialized result %s does not contain %s", encoded, field)
		}
	}
}

func TestTimestampMs(t *testing.T) {
	if got, want := timestampMs(1_700_000_000, 123_456_789), int64(1_700_000_000_123); got != want {
		t.Fatalf("timestampMs() = %d, want %d", got, want)
	}
}

func TestEmptyPolicyHasNonNilClasses(t *testing.T) {
	if policy := emptyPolicy(); policy.Classes == nil {
		t.Fatal("emptyPolicy().Classes must be a non-nil empty slice")
	}
}
