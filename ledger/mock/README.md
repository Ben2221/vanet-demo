# In-memory mock ledger

The mock implements the currently deployed REST gateway contract using FastAPI
and Uvicorn. It keeps config, roots, policies, auth records, reports,
revocations, traces, and activity in process memory; restarting it resets all
state. It does not connect to Fabric or persist data.

## Start

From the repository root:

```bash
python -m pip install -r ledger/mock/requirements.txt
python ledger/mock/mock_ledger_server.py
```

The default URL is `http://127.0.0.1:3000`. Set `PORT` to use another port
(for example, `PORT=3001` in Git Bash or `$env:PORT = '3001'` in PowerShell).
`HOST` defaults to `127.0.0.1`. `MOCK_COMMIT_MS` controls the numeric `commitMs`
returned for writes; it defaults to `600`. The mock does not sleep to simulate
that duration.

The header `X-Identity` selects a caller: names beginning with `ta` are TA
identities and names beginning with `rsu` are RSUs. Omitting the header uses
`ta1` for TA-only routes and `rsu1` otherwise. This is a demo convention, not
authentication.

## Conformance suite

Run the same conformance file against either backend by selecting `LEDGER` and
`LEDGER_URL`:

```bash
LEDGER=mock LEDGER_URL=http://127.0.0.1:3001 python -m pytest ledger/tests/test_conformance.py -q
LEDGER=gateway LEDGER_URL=http://127.0.0.1:3000 python -m pytest ledger/tests/test_conformance.py -q
```

The Fabric report-MVCC concurrency case is skipped for the mock because the
mock serializes writes rather than simulating Fabric validation conflicts. The
trace approval concurrency test still runs. Skipped chaincode functions return
HTTP 501 with `{ "ok": false, "error": { "code": "NOT_DEPLOYED" } }`.
