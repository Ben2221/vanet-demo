package main

const (
	roleTA       = "TA"
	roleRSU      = "RSU"
	roleUnknown  = "UNKNOWN"
	mspTA        = "Org1MSP"
	mspRSU       = "Org2MSP"
	configKey    = "config"
	rootObject   = "root"
	policyObject = "policy"
	authObject   = "auth"
	reportObject = "rep"
	revObject    = "rev"
	traceObject  = "trace"
	maxListItems = 1000
)

type Config struct {
	K              int  `json:"K"`
	TraceThreshold int  `json:"traceThreshold"`
	MaxAuthTtlSec  int  `json:"maxAuthTtlSec"`
	DemoMode       bool `json:"demoMode"`
}

type Root struct {
	Epoch        int64  `json:"epoch"`
	MerkleRoot   string `json:"merkleRoot"`
	ValidUntil   int64  `json:"validUntil"`
	RegisteredTs int64  `json:"registeredTs"`
}

type Policy struct {
	Service   string   `json:"service"`
	Classes   []string `json:"classes"`
	UpdatedTs int64    `json:"updatedTs"`
}

type AuthRecord struct {
	PID          string `json:"pid"`
	Service      string `json:"service"`
	Class        string `json:"class"`
	Expiry       int64  `json:"expiry"`
	RSUID        string `json:"rsuId"`
	FirstTs      int64  `json:"firstTs"`
	Ts           int64  `json:"ts"`
	SessionCount int    `json:"sessionCount"`
}

type MisbehaviourReport struct {
	PID          string `json:"pid"`
	RSUID        string `json:"rsuId"`
	EvidenceHash string `json:"evidenceHash"`
	AttackType   string `json:"attackType"`
	Ts           int64  `json:"ts"`
}

type Revocation struct {
	PID           string   `json:"pid"`
	Reason        string   `json:"reason"`
	Reporters     []string `json:"reporters"`
	FirstReportTs int64    `json:"firstReportTs"`
	RevokedTs     int64    `json:"revokedTs"`
	Source        string   `json:"source"`
	ReqID         string   `json:"reqId,omitempty" metadata:"reqId,optional"`
}

type ReportResult struct {
	PID            string `json:"pid"`
	ReportCount    int    `json:"reportCount"`
	K              int    `json:"K"`
	Revoked        bool   `json:"revoked"`
	NewlyRevoked   bool   `json:"newlyRevoked"`
	Duplicate      bool   `json:"duplicate"`
	AlreadyRevoked bool   `json:"alreadyRevoked"`
}

type CheckAccessResult struct {
	Allow      bool       `json:"allow"`
	Reasons    []string   `json:"reasons"`
	ActiveAuth AuthRecord `json:"activeAuth"`
}

type PseudonymStatus struct {
	PID           string     `json:"pid"`
	Revoked       bool       `json:"revoked"`
	RevokedTs     int64      `json:"revokedTs"`
	ReportCount   int        `json:"reportCount"`
	Reporters     []string   `json:"reporters"`
	FirstReportTs int64      `json:"firstReportTs"`
	ActiveAuth    AuthRecord `json:"activeAuth"`
}

type Caller struct {
	MSP  string
	ID   string
	Role string
}

type WhoAmIResult struct {
	MSP  string `json:"msp"`
	Role string `json:"role"`
	ID   string `json:"id"`
}

type TraceRecord struct {
	ReqID       string   `json:"reqId"`
	PID         string   `json:"pid"`
	Reason      string   `json:"reason"`
	Requester   string   `json:"requester"`
	Status      string   `json:"status"`
	Threshold   int      `json:"threshold"`
	Approvals   []string `json:"approvals"`
	RevokedPids []string `json:"revokedPids"`
	CreatedTs   int64    `json:"createdTs"`
	ApprovedTs  int64    `json:"approvedTs"`
	ExecutedTs  int64    `json:"executedTs"`
}
