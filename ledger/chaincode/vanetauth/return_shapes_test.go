package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/hyperledger/fabric-chaincode-go/shimtest"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	fabricmsp "github.com/hyperledger/fabric-protos-go/msp"
)

func TestExportedContractReturnTypesAreJSONSafe(t *testing.T) {
	contractType := reflect.TypeOf(&VanetAuth{})
	baseType := reflect.TypeOf(&contractapi.Contract{})
	baseMethods := make(map[string]struct{}, baseType.NumMethod())
	for index := 0; index < baseType.NumMethod(); index++ {
		baseMethods[baseType.Method(index).Name] = struct{}{}
	}

	for _, legacyMethod := range []string{"Put", "Get"} {
		if _, found := contractType.MethodByName(legacyMethod); found {
			t.Fatalf("legacy contract method %s is still exported", legacyMethod)
		}
	}

	functionCount := 0
	for index := 0; index < contractType.NumMethod(); index++ {
		method := contractType.Method(index)
		if _, inherited := baseMethods[method.Name]; inherited {
			continue
		}
		functionCount++
		for outputIndex := 0; outputIndex < method.Type.NumOut(); outputIndex++ {
			output := method.Type.Out(outputIndex)
			if output == reflect.TypeOf((*error)(nil)).Elem() && outputIndex == method.Type.NumOut()-1 {
				continue
			}
			assertJSONSafeType(t, method.Name+" return", output)
		}
	}
	if functionCount != 21 {
		t.Fatalf("reflected %d contract functions; want 21 deployed business functions and WhoAmI", functionCount)
	}

	stub := shimtest.NewMockStub("return-shape-test", nil)
	stub.TxTimestamp = &timestamp.Timestamp{Seconds: 1_700_000_000}
	ctx := &contractapi.TransactionContext{}
	ctx.SetStub(stub)
	contract := &VanetAuth{}

	roots, err := contract.ListRoots(ctx)
	assertNonNilSlice(t, "ListRoots", roots, err)
	policies, err := contract.ListPolicies(ctx)
	assertNonNilSlice(t, "ListPolicies", policies, err)
	auths, err := contract.ListAuthsSince(ctx, "0")
	assertNonNilSlice(t, "ListAuthsSince", auths, err)
	revoked, err := contract.ListRevokedSince(ctx, "0")
	assertNonNilSlice(t, "ListRevokedSince", revoked, err)

	missingPolicy, err := contract.GetPolicy(ctx, "empty-policy")
	if err == nil {
		t.Fatal("GetPolicy for a missing policy unexpectedly succeeded")
	}
	if missingPolicy.Classes == nil {
		t.Fatal("GetPolicy returned nil classes for its empty error result")
	}

	access, err := contract.CheckAccess(ctx, strings.Repeat("a", 64), "private", "traffic-info")
	if err != nil {
		t.Fatalf("CheckAccess on empty state: %v", err)
	}
	if access.Reasons == nil {
		t.Fatal("CheckAccess returned nil reasons")
	}
	status, err := contract.GetPseudonymStatus(ctx, strings.Repeat("a", 64))
	if err != nil {
		t.Fatalf("GetPseudonymStatus on empty state: %v", err)
	}
	if status.Reporters == nil {
		t.Fatal("GetPseudonymStatus returned nil reporters")
	}
}

func TestDemoContractResponsesPassContractAPISchema(t *testing.T) {
	chaincode, err := contractapi.NewChaincode(&VanetAuth{})
	if err != nil {
		t.Fatalf("create contract API chaincode: %v", err)
	}
	stub := shimtest.NewMockStub("demo-response-schema", chaincode)
	taCreator := serializedTestCreator(t, mspTA, "ta1")
	rsu1Creator := serializedTestCreator(t, mspRSU, "rsu1")
	rsu2Creator := serializedTestCreator(t, mspRSU, "rsu2")
	rsu3Creator := serializedTestCreator(t, mspRSU, "rsu3")
	transactionNumber := 0
	invoke := func(creator []byte, function string, arguments ...string) json.RawMessage {
		t.Helper()
		transactionNumber++
		stub.Creator = creator
		invokeArgs := [][]byte{[]byte("VanetAuth:" + function)}
		for _, argument := range arguments {
			invokeArgs = append(invokeArgs, []byte(argument))
		}
		response := stub.MockInvoke("schema-"+strconv.Itoa(transactionNumber), invokeArgs)
		if response.Status != 200 {
			t.Fatalf("%s contract invocation failed (%d): %s", function, response.Status, response.Message)
		}
		return append(json.RawMessage(nil), response.Payload...)
	}

	assertObject := func(name string, creator []byte, function string, arguments []string, fields []string) json.RawMessage {
		t.Helper()
		payload := invoke(creator, function, arguments...)
		assertJSONObjectPayload(t, name, payload, fields)
		return payload
	}
	assertArray := func(name string, creator []byte, function string, arguments []string, fields []string) {
		t.Helper()
		payload := invoke(creator, function, arguments...)
		assertJSONArrayPayload(t, name, payload, fields)
	}
	assertError := func(name string, creator []byte, function string, arguments []string, code string) {
		t.Helper()
		transactionNumber++
		stub.Creator = creator
		invokeArgs := [][]byte{[]byte("VanetAuth:" + function)}
		for _, argument := range arguments {
			invokeArgs = append(invokeArgs, []byte(argument))
		}
		response := stub.MockInvoke("schema-"+strconv.Itoa(transactionNumber), invokeArgs)
		if response.Status == 200 {
			t.Fatalf("%s unexpectedly succeeded: %s", name, response.Payload)
		}
		if !strings.Contains(response.Message, code) && !strings.Contains(string(response.Payload), code) {
			t.Fatalf("%s error = %q, want %s", name, response.Message, code)
		}
	}

	const service = "schema-service"
	const authPID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const reportPID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	const rootHash = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	const evidence1 = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	const evidence2 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	const evidence3 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	rootValidUntil := strconv.FormatInt(time.Now().Add(time.Hour).UnixMilli(), 10)
	authExpiry := strconv.FormatInt(time.Now().Add(10*time.Minute).UnixMilli(), 10)

	assertJSONObjectPayload(t, "WhoAmI", invoke(taCreator, "WhoAmI"), []string{"msp", "role", "id"})
	assertObject("SetConfig", taCreator, "SetConfig", []string{"2", "3", "3600", "true"}, []string{
		"K", "traceThreshold", "maxAuthTtlSec", "demoMode",
	})
	assertJSONObjectPayload(t, "GetConfig", invoke(rsu1Creator, "GetConfig"), []string{
		"K", "traceThreshold", "maxAuthTtlSec", "demoMode",
	})
	assertObject("SetPolicy", taCreator, "SetPolicy", []string{service, `["private","commercial"]`}, []string{
		"service", "classes", "updatedTs",
	})
	assertJSONObjectPayload(t, "GetPolicy", invoke(rsu1Creator, "GetPolicy", service), []string{
		"service", "classes", "updatedTs",
	})
	assertArray("ListPolicies", rsu1Creator, "ListPolicies", nil, []string{"service", "classes", "updatedTs"})

	assertObject("RegisterRoot", taCreator, "RegisterRoot", []string{"42", rootHash, rootValidUntil}, []string{
		"epoch", "merkleRoot", "validUntil", "registeredTs",
	})
	assertJSONObjectPayload(t, "GetRoot", invoke(rsu1Creator, "GetRoot", "42"), []string{
		"epoch", "merkleRoot", "validUntil", "registeredTs",
	})
	assertArray("ListRoots", rsu1Creator, "ListRoots", nil, []string{
		"epoch", "merkleRoot", "validUntil", "registeredTs",
	})

	authFields := []string{"pid", "service", "class", "expiry", "rsuId", "firstTs", "ts", "sessionCount"}
	assertJSONObjectPayload(t, "RecordAuth", invoke(rsu1Creator, "RecordAuth", authPID, service, "private", authExpiry), authFields)
	assertJSONObjectPayload(t, "GetAuth", invoke(rsu2Creator, "GetAuth", authPID), authFields)
	assertArray("ListAuthsSince", rsu2Creator, "ListAuthsSince", []string{"0"}, authFields)

	assertion := assertObject("CheckAccess", rsu2Creator, "CheckAccess", []string{authPID, "private", service}, []string{
		"allow", "reasons", "activeAuth",
	})
	assertNestedObjectFields(t, "CheckAccess.activeAuth", assertion, "activeAuth", authFields)
	statusFields := []string{"pid", "revoked", "revokedTs", "reportCount", "reporters", "firstReportTs", "activeAuth"}
	status := assertJSONObjectPayload(t, "GetPseudonymStatus", invoke(rsu2Creator, "GetPseudonymStatus", authPID), statusFields)
	assertNestedObjectFields(t, "GetPseudonymStatus.activeAuth", status, "activeAuth", authFields)
	var notRevoked bool
	if err := json.Unmarshal(invoke(rsu2Creator, "IsRevoked", authPID), &notRevoked); err != nil || notRevoked {
		t.Fatalf("IsRevoked before a report = %v, err %v; want false", notRevoked, err)
	}

	reportFields := []string{"pid", "reportCount", "K", "revoked", "newlyRevoked", "duplicate", "alreadyRevoked"}
	fresh := assertJSONObjectPayload(t, "ReportMisbehaviour fresh", invoke(rsu1Creator, "ReportMisbehaviour", reportPID, evidence1, "sybil"), reportFields)
	assertJSONField(t, "fresh reportCount", fresh, "reportCount", "1")
	duplicate := assertJSONObjectPayload(t, "ReportMisbehaviour duplicate", invoke(rsu1Creator, "ReportMisbehaviour", reportPID, evidence2, "sybil"), reportFields)
	assertJSONField(t, "duplicate flag", duplicate, "duplicate", "true")
	assertJSONField(t, "duplicate reportCount", duplicate, "reportCount", "1")
	newlyRevoked := assertJSONObjectPayload(t, "ReportMisbehaviour threshold", invoke(rsu2Creator, "ReportMisbehaviour", reportPID, evidence3, "sybil"), reportFields)
	assertJSONField(t, "threshold revoked", newlyRevoked, "revoked", "true")
	assertJSONField(t, "threshold newlyRevoked", newlyRevoked, "newlyRevoked", "true")
	alreadyRevoked := assertJSONObjectPayload(t, "ReportMisbehaviour already revoked", invoke(rsu1Creator, "ReportMisbehaviour", reportPID, evidence1, "sybil"), reportFields)
	assertJSONField(t, "already revoked flag", alreadyRevoked, "alreadyRevoked", "true")
	assertJSONField(t, "already revoked state", alreadyRevoked, "revoked", "true")
	assertJSONField(t, "already revoked reportCount", alreadyRevoked, "reportCount", "2")

	var isRevoked bool
	if err := json.Unmarshal(invoke(rsu2Creator, "IsRevoked", reportPID), &isRevoked); err != nil || !isRevoked {
		t.Fatalf("IsRevoked after threshold = %v, err %v; want true", isRevoked, err)
	}
	revokedFields := []string{"pid", "reason", "reporters", "firstReportTs", "revokedTs", "source"}
	assertArray("ListRevokedSince", rsu1Creator, "ListRevokedSince", []string{"0"}, revokedFields)
	status = assertJSONObjectPayload(t, "GetPseudonymStatus after revocation", invoke(rsu1Creator, "GetPseudonymStatus", reportPID), statusFields)
	assertNestedObjectFields(t, "revoked status.activeAuth", status, "activeAuth", authFields)

	traceFields := []string{
		"reqId", "pid", "reason", "requester", "status", "threshold", "approvals",
		"revokedPids", "createdTs", "approvedTs", "executedTs",
	}
	traceID := "schema-trace-approved"
	trace := assertObject("RequestTrace", rsu1Creator, "RequestTrace", []string{traceID, reportPID, "schema test"}, traceFields)
	assertJSONField(t, "new trace status", trace, "status", `"PENDING"`)
	assertJSONField(t, "new trace approvals", trace, "approvals", `[]`)
	assertJSONField(t, "new trace revokedPids", trace, "revokedPids", `[]`)
	assertJSONField(t, "new trace approvedTs", trace, "approvedTs", "0")
	assertJSONField(t, "new trace executedTs", trace, "executedTs", "0")
	assertJSONObjectPayload(t, "GetTrace pending", invoke(taCreator, "GetTrace", traceID), traceFields)
	assertError("RequestTrace non-revoked pid", rsu1Creator, "RequestTrace", []string{"schema-unrevoked", authPID, "schema test"}, "ERR_CONFLICT")
	assertError("RequestTrace duplicate reqId", rsu2Creator, "RequestTrace", []string{traceID, reportPID, "schema test"}, "ERR_CONFLICT")
	assertError("GetTrace missing", rsu1Creator, "GetTrace", []string{"schema-missing-trace"}, "ERR_NOT_FOUND")
	assertError("ApproveTrace TA forbidden", taCreator, "ApproveTrace", []string{traceID}, "ERR_FORBIDDEN")

	firstApproval := assertJSONObjectPayload(t, "ApproveTrace first", invoke(rsu1Creator, "ApproveTrace", traceID), traceFields)
	assertJSONField(t, "first approval remains pending", firstApproval, "status", `"PENDING"`)
	assertError("ApproveTrace duplicate", rsu1Creator, "ApproveTrace", []string{traceID}, "ERR_CONFLICT")
	assertJSONObjectPayload(t, "ApproveTrace second", invoke(rsu2Creator, "ApproveTrace", traceID), traceFields)
	approvedTrace := assertJSONObjectPayload(t, "ApproveTrace threshold", invoke(rsu3Creator, "ApproveTrace", traceID), traceFields)
	assertJSONField(t, "trace at threshold is approved", approvedTrace, "status", `"APPROVED"`)
	assertJSONObjectPayload(t, "GetTrace approved", invoke(taCreator, "GetTrace", traceID), traceFields)

	pendingID := "schema-trace-pending"
	assertJSONObjectPayload(t, "RequestTrace for pending revoke", invoke(taCreator, "RequestTrace", pendingID, reportPID, "schema pending"), traceFields)
	assertError("Revoke pending trace", taCreator, "Revoke", []string{pendingID, `[` + `"` + reportPID + `"` + `]`, "schema reason"}, "ERR_CONFLICT")

	otherPID := "1111111111111111111111111111111111111111111111111111111111111111"
	assertError("Revoke without traced pid", taCreator, "Revoke", []string{traceID, `["` + otherPID + `"]`, "schema reason"}, "ERR_BAD_INPUT")
	assertError("Revoke invalid pid", taCreator, "Revoke", []string{traceID, `["BAD"]`, "schema reason"}, "ERR_BAD_INPUT")
	assertError("Revoke RSU forbidden", rsu1Creator, "Revoke", []string{traceID, `["` + reportPID + `"]`, "schema reason"}, "ERR_FORBIDDEN")

	tracePID2 := "2222222222222222222222222222222222222222222222222222222222222222"
	tracePID3 := "3333333333333333333333333333333333333333333333333333333333333333"
	revokePIDs := `["` + reportPID + `","` + tracePID2 + `","` + tracePID3 + `"]`
	executedTrace := assertJSONObjectPayload(t, "Revoke approved trace", invoke(taCreator, "Revoke", traceID, revokePIDs, "schema reason"), traceFields)
	assertJSONField(t, "trace is executed", executedTrace, "status", `"EXECUTED"`)
	var executedTraceFields map[string]json.RawMessage
	if err := json.Unmarshal(executedTrace, &executedTraceFields); err != nil {
		t.Fatalf("decode executed trace: %v", err)
	}
	var executedTs int64
	if err := json.Unmarshal(executedTraceFields["executedTs"], &executedTs); err != nil || executedTs <= 0 {
		t.Fatalf("executedTs = %d, err %v; want a positive transaction timestamp", executedTs, err)
	}
	assertJSONField(t, "trace revokedPids", executedTrace, "revokedPids", revokePIDs)
	assertError("Revoke executed trace twice", taCreator, "Revoke", []string{traceID, revokePIDs, "schema reason"}, "ERR_CONFLICT")
	assertJSONObjectPayload(t, "GetTrace executed", invoke(rsu2Creator, "GetTrace", traceID), traceFields)
}

func serializedTestCreator(t *testing.T, mspID, commonName string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test certificate key: %v", err)
	}
	certificateTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Unix(0, 0),
		NotAfter:              time.Unix(4_102_444_800, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, certificateTemplate, certificateTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create test certificate: %v", err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	creator, err := proto.Marshal(&fabricmsp.SerializedIdentity{Mspid: mspID, IdBytes: certificatePEM})
	if err != nil {
		t.Fatalf("marshal test creator identity: %v", err)
	}
	return creator
}

func assertJSONSafeType(t *testing.T, path string, valueType reflect.Type) {
	t.Helper()
	switch valueType.Kind() {
	case reflect.Interface, reflect.Pointer, reflect.Map:
		t.Errorf("%s has disallowed type %s", path, valueType)
	case reflect.Slice:
		assertJSONSafeType(t, path+" element", valueType.Elem())
	case reflect.Struct:
		for fieldIndex := 0; fieldIndex < valueType.NumField(); fieldIndex++ {
			field := valueType.Field(fieldIndex)
			if !field.IsExported() {
				continue
			}
			assertJSONSafeType(t, path+"."+field.Name, field.Type)
		}
	default:
		switch valueType.Kind() {
		case reflect.String, reflect.Bool,
			reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			return
		default:
			t.Errorf("%s has unsupported JSON type %s", path, valueType)
		}
	}
}

func assertNonNilSlice[T any](t *testing.T, name string, values []T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s on empty state: %v", name, err)
	}
	if values == nil {
		t.Fatalf("%s returned a nil slice", name)
	}
}

func assertJSONObjectPayload(t *testing.T, name string, payload json.RawMessage, expected []string) json.RawMessage {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(payload, &object); err != nil {
		t.Fatalf("decode %s as object: %v (JSON %s)", name, err, payload)
	}
	assertFieldNames(t, name, object, expected)
	return payload
}

func assertJSONArrayPayload(t *testing.T, name string, payload json.RawMessage, expected []string) {
	t.Helper()
	var array []json.RawMessage
	if err := json.Unmarshal(payload, &array); err != nil {
		t.Fatalf("decode %s as array: %v (JSON %s)", name, err, payload)
	}
	if array == nil || len(array) == 0 {
		t.Fatalf("%s did not return a non-empty JSON array: %s", name, payload)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(array[0], &object); err != nil {
		t.Fatalf("decode %s item as object: %v", name, err)
	}
	assertFieldNames(t, name, object, expected)
	for _, field := range []string{"classes", "reporters"} {
		if value, exists := object[field]; exists && string(value) == "null" {
			t.Errorf("%s.%s is null, want an array", name, field)
		}
	}
}

func assertNestedObjectFields(t *testing.T, name string, payload json.RawMessage, field string, expected []string) {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(payload, &object); err != nil {
		t.Fatalf("decode %s parent: %v", name, err)
	}
	var nested map[string]json.RawMessage
	if err := json.Unmarshal(object[field], &nested); err != nil {
		t.Fatalf("decode %s as object: %v (JSON %s)", name, err, object[field])
	}
	assertFieldNames(t, name, nested, expected)
}

func assertJSONField(t *testing.T, name string, payload json.RawMessage, field, expected string) {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(payload, &object); err != nil {
		t.Fatalf("decode %s parent: %v", name, err)
	}
	if actual := string(object[field]); actual != expected {
		t.Errorf("%s = %s, want %s", name, actual, expected)
	}
}

func assertFieldNames(t *testing.T, name string, object map[string]json.RawMessage, expected []string) {
	t.Helper()
	actual := make([]string, 0, len(object))
	for field := range object {
		actual = append(actual, field)
	}
	sort.Strings(actual)
	want := append([]string(nil), expected...)
	sort.Strings(want)
	if !reflect.DeepEqual(actual, want) {
		t.Errorf("%s fields = %v, want %v", name, actual, want)
	}
}
