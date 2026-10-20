package main

import (
	"strconv"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// Trust-weighted revocation (--trust-weighted): every RSU's reports count with a
// weight in 0..1000 (per mille, default 1000). A pseudonym is revoked once the weights
// of its distinct reporters sum to K * 1000, so without any weight set this is exactly
// the K-of-RSUs rule. The TA lowers an RSU's weight after investigations found its
// reports wrong (SetReporterWeight).

const (
	weightObject = "weight"
	fullWeight   = 1000
)

type ReporterWeight struct {
	RSUID       string `json:"rsuId"`
	WeightMilli int    `json:"weightMilli"`
	UpdatedTs   int64  `json:"updatedTs"`
}

func (c *VanetAuth) SetReporterWeight(ctx contractapi.TransactionContextInterface, rsuID, weightMilli string) (ReporterWeight, error) {
	if _, err := requireRole(ctx, roleTA); err != nil {
		return ReporterWeight{}, err
	}
	if err := validateSafeString("rsuId", rsuID); err != nil {
		return ReporterWeight{}, err
	}
	value, err := strconv.Atoi(weightMilli)
	if err != nil || value < 0 || value > fullWeight {
		return ReporterWeight{}, errf("ERR_BAD_INPUT", "weightMilli must be an integer between 0 and %d", fullWeight)
	}
	now, err := nowMs(ctx)
	if err != nil {
		return ReporterWeight{}, err
	}
	key, err := createCompositeKey(ctx.GetStub(), weightObject, rsuID)
	if err != nil {
		return ReporterWeight{}, err
	}
	weight := ReporterWeight{RSUID: rsuID, WeightMilli: value, UpdatedTs: now}
	encoded, err := marshalState(weight)
	if err != nil {
		return ReporterWeight{}, err
	}
	return weight, ctx.GetStub().PutState(key, encoded)
}

func (c *VanetAuth) GetReporterWeight(ctx contractapi.TransactionContextInterface, rsuID string) (ReporterWeight, error) {
	if err := validateSafeString("rsuId", rsuID); err != nil {
		return ReporterWeight{}, err
	}
	value, err := reporterWeight(ctx.GetStub(), rsuID)
	return ReporterWeight{RSUID: rsuID, WeightMilli: value}, err
}

func reporterWeight(stub shim.ChaincodeStubInterface, rsuID string) (int, error) {
	key, err := createCompositeKey(stub, weightObject, rsuID)
	if err != nil {
		return 0, err
	}
	raw, err := stub.GetState(key)
	if err != nil || len(raw) == 0 {
		return fullWeight, err
	}
	var weight ReporterWeight
	if err := unmarshalState(raw, &weight); err != nil {
		return 0, err
	}
	return weight.WeightMilli, nil
}

// weightSum of distinct reporters, per mille.
func weightSum(stub shim.ChaincodeStubInterface, reporters []string) (int, error) {
	total := 0
	for _, rsuID := range reporters {
		value, err := reporterWeight(stub, rsuID)
		if err != nil {
			return 0, err
		}
		total += value
	}
	return total, nil
}
