package main

import (
	"strconv"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func defaultConfig() Config {
	return Config{K: 2, TraceThreshold: 3, MaxAuthTtlSec: 3600, DemoMode: true}
}

func (c *VanetAuth) SetConfig(ctx contractapi.TransactionContextInterface, k, traceThreshold, maxAuthTtlSec, demoMode string) (Config, error) {
	if _, err := requireRole(ctx, roleTA); err != nil {
		return Config{}, err
	}
	kValue, err := parseIntArg("K", k)
	if err != nil {
		return Config{}, err
	}
	thresholdValue, err := parseIntArg("traceThreshold", traceThreshold)
	if err != nil {
		return Config{}, err
	}
	ttlValue, err := parseIntArg("maxAuthTtlSec", maxAuthTtlSec)
	if err != nil {
		return Config{}, err
	}
	if kValue < 1 || kValue > 10 {
		return Config{}, errf("ERR_BAD_INPUT", "K must be between 1 and 10")
	}
	if thresholdValue < 1 || thresholdValue > 10 {
		return Config{}, errf("ERR_BAD_INPUT", "traceThreshold must be between 1 and 10")
	}
	if ttlValue < 60 || ttlValue > 86400 {
		return Config{}, errf("ERR_BAD_INPUT", "maxAuthTtlSec must be between 60 and 86400")
	}
	if err := validateSafeString("demoMode", demoMode); err != nil {
		return Config{}, err
	}
	mode, err := strconv.ParseBool(demoMode)
	if err != nil {
		return Config{}, errf("ERR_BAD_INPUT", "demoMode must be a boolean")
	}

	configuration := Config{
		K:              int(kValue),
		TraceThreshold: int(thresholdValue),
		MaxAuthTtlSec:  int(ttlValue),
		DemoMode:       mode,
	}
	encoded, err := marshalState(configuration)
	if err != nil {
		return Config{}, err
	}
	if err := ctx.GetStub().PutState(configKey, encoded); err != nil {
		return Config{}, err
	}
	return configuration, nil
}

func (c *VanetAuth) GetConfig(ctx contractapi.TransactionContextInterface) (Config, error) {
	encoded, err := ctx.GetStub().GetState(configKey)
	if err != nil {
		return Config{}, err
	}
	if len(encoded) == 0 {
		return defaultConfig(), nil
	}
	var configuration Config
	if err := unmarshalState(encoded, &configuration); err != nil {
		return Config{}, err
	}
	return configuration, nil
}
