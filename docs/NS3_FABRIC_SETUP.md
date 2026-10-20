# Running with ns-3 and real Hyperledger Fabric

The full stack: ns-3 802.11p radio, the real protocol, and the `vanetauth` chaincode on a real
Fabric 2.5.9 network (2 orgs, Raft orderer, 500 ms batch timeout) behind the REST gateway.
Tested on Linux; on Windows use WSL2.

## 1. ns-3

```bash
pip install ns3                                   # ns-3 3.44+ Python bindings
python network/range_test.py --backend ns3        # must print PASS (arrive at 300 m, fail at 450 m)
```

## 2. Fabric

```bash
export RSU_COUNT=9            # one Fabric identity per simulated RSU (grid: 9, Monaco: 27)
./ledger/start.sh             # installs Fabric, starts the network, deploys vanetauth,
                              # enrolls ta1 + rsu1..rsu$RSU_COUNT, smoke test, seed
cd ledger/gateway && npm ci && RSU_COUNT=9 npm start      # REST gateway on :3000
curl localhost:3000/health                        # {"gateway":"up","chaincode":"ok",...}
LEDGER_URL=http://localhost:3000 pytest ledger/tests/test_conformance.py     # 27 passed
```

**Why one identity per RSU.** The chaincode counts *different* RSU identities: two reports to
revoke, `t = 2f+1` approvals to reveal (5 of 9). With fewer identities than simulated RSUs, the
client folds RSUs together and those rules are not what you measure; with 4 identities a 5-of-9
trace can never be approved. The chaincode caps the trace threshold at 10, so Monaco (27 RSUs,
`t = 17`) needs `--trace-threshold 10` or a chaincode change.

## 3. Run

```bash
export LEDGER_RSU_IDENTITIES=rsu1,rsu2,rsu3,rsu4,rsu5,rsu6,rsu7,rsu8,rsu9
python network/run_scenario.py --backend ns3 --ledger http://localhost:3000 --protocol real \
       --vehicles 60 --duration 120 --attacker-ratio 0.1 --attack random_pos --attack-start 20
python experiments/run.py --config experiments/configs/final_schemes.json --jobs 4
python experiments/run.py --config experiments/configs/final_attacks.json --jobs 4
```

A 120 s, 60-vehicle run takes about 3.5 min.

## Pitfalls we hit (and the fixes in this repository)

| Symptom | Cause | Fix |
|---|---|---|
| `Permission denied` running `ledger/start.sh` | scripts committed without the executable bit | fixed in git (`chmod +x`) |
| chaincode install: `docker build failed: write: broken pipe` / `unexpected EOF` | Fabric 2.5's peer builds chaincode with Docker's legacy builder and an old API version; **Docker 29** rejects the old API and breaks the legacy build stream | use **Docker ≤ 24** (e.g. the static `docker-24.0.9` binaries), or Chaincode-as-a-Service |
| `golang:1.20` pull: `429 Too Many Requests` | Docker Hub anonymous rate limit (the chaincode pre-build check runs in that image) | `LOCAL_GO=$(which go) ./ledger/start.sh` runs the same checks with an installed Go |
| enroll: `connection refused :7054` | crypto material from an earlier attempt was still there, so `network.sh` skipped starting the CAs | `./ledger/network/down.sh` before restarting, or `docker compose -f compose/compose-ca.yaml up -d` in `test-network` |
| `revoke ... 409 trace request must be approved` | the client guessed the trace from the pseudonyms and picked another, still pending, trace of the same vehicle | the TA now passes the approved trace id (`req_id`); the in-memory ledger enforces the same rule |
| identity reveal 20+ s, some attackers never revealed | RSUs approve the same trace in the same block; Fabric validates one write per key and block (MVCC conflict, `TX_CONFLICT`), and the client treated that 409 as "already approved" | the client retries `TX_CONFLICT`; the retry time counts as commit time |
