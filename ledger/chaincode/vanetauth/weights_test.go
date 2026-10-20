package main

import (
	"strings"
	"testing"

	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/hyperledger/fabric-chaincode-go/shimtest"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func TestTrustWeightedRevocation(t *testing.T) {
	chaincode, err := contractapi.NewChaincode(&VanetAuth{})
	if err != nil {
		t.Fatal(err)
	}
	stub := shimtest.NewMockStub("weights", chaincode)
	stub.TxTimestamp = &timestamp.Timestamp{Seconds: 1_700_000_000}
	ta := serializedTestCreator(t, mspTA, "ta1")
	rsu := func(name string) []byte { return serializedTestCreator(t, mspRSU, name) }
	n := 0
	invoke := func(creator []byte, args ...string) (int32, string) {
		n++
		stub.Creator = creator
		raw := [][]byte{[]byte("VanetAuth:" + args[0])}
		for _, a := range args[1:] {
			raw = append(raw, []byte(a))
		}
		r := stub.MockInvoke("tx"+strings.Repeat("x", n), raw)
		return r.Status, string(r.Payload) + r.Message
	}
	pid1, pid2 := strings.Repeat("a", 64), strings.Repeat("b", 64)
	ev := strings.Repeat("c", 64)

	// default weights: plain K = 2
	invoke(rsu("rsu1"), "ReportMisbehaviour", pid1, ev, "")
	if _, out := invoke(rsu("rsu2"), "ReportMisbehaviour", pid1, ev, ""); !strings.Contains(out, `"revoked":true`) {
		t.Fatalf("two full-weight reports must revoke: %s", out)
	}
	// RSU cannot set weights
	if status, _ := invoke(rsu("rsu1"), "SetReporterWeight", "rsu1", "1000"); status == 200 {
		t.Fatal("an RSU set a weight")
	}
	if status, out := invoke(ta, "SetReporterWeight", "rsu7", "500"); status != 200 {
		t.Fatalf("TA SetReporterWeight: %s", out)
	}
	invoke(ta, "SetReporterWeight", "rsu8", "500")
	invoke(rsu("rsu7"), "ReportMisbehaviour", pid2, ev, "")
	if _, out := invoke(rsu("rsu8"), "ReportMisbehaviour", pid2, ev, ""); strings.Contains(out, `"revoked":true`) {
		t.Fatalf("0.5 + 0.5 < K must not revoke: %s", out)
	}
	if _, out := invoke(rsu("rsu1"), "ReportMisbehaviour", pid2, ev, ""); !strings.Contains(out, `"revoked":true`) {
		t.Fatalf("0.5 + 0.5 + 1 >= K must revoke: %s", out)
	}
	if status, _ := invoke(ta, "SetReporterWeight", "rsu7", "1001"); status == 200 {
		t.Fatal("weight above 1000 accepted")
	}
}
