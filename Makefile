# Shortcuts for the common tasks. `make help` lists them.
# Variables can be overridden: make run VEHICLES=150 DURATION=300 BACKEND=ns3

PY       := .venv/bin/python
export PYTHONWARNINGS := ignore
export MPLBACKEND := Agg

VEHICLES ?= 100
DURATION ?= 120
SEED     ?= 1
BACKEND  ?= auto
PROTOCOL ?= real
ATTACK   ?= 0.1
PORT     ?= 3000
LEDGER   ?= mock
JOBS     ?= 4

.PHONY: help setup test test-ledger run run-ns3 quick compare show mock gateway fabric-up fabric-down clean-results

help:
	@echo "make setup          create .venv and install everything (./setup.sh)"
	@echo "make test           all Python tests"
	@echo "make test-ledger    ledger conformance tests against a running mock (make mock) on PORT"
	@echo "make run            one scenario: VEHICLES=$(VEHICLES) DURATION=$(DURATION) PROTOCOL=$(PROTOCOL) BACKEND=$(BACKEND)"
	@echo "make run-ns3        same, forced onto ns-3, with NetAnim output"
	@echo "make quick          6-run sweep (experiments/configs/quick_real.json), tables and figures"
	@echo "make compare        ours vs stub vs ECDSA PKI vs central authority (compare_real.json)"
	@echo "make show           key numbers of every run under experiments/results/"
	@echo "make mock           in-memory ledger REST server on PORT=$(PORT)"
	@echo "make gateway        Fabric REST gateway on PORT=$(PORT) (needs make fabric-up)"
	@echo "make fabric-up      install and start Hyperledger Fabric in Docker"
	@echo "make fabric-down    stop Fabric and delete its containers"
	@echo "Use another ledger: make run LEDGER=http://127.0.0.1:$(PORT)"

$(PY):
	./setup.sh

setup:
	./setup.sh

test: $(PY)
	$(PY) -m pytest -q

test-ledger: $(PY)
	LEDGER=mock LEDGER_URL=http://127.0.0.1:$(PORT) $(PY) -m pytest -q ledger/tests

run: $(PY)
	$(PY) network/run_scenario.py --vehicles $(VEHICLES) --duration $(DURATION) --seed $(SEED) \
	    --backend $(BACKEND) --protocol $(PROTOCOL) --attacker-ratio $(ATTACK) --ledger $(LEDGER)

run-ns3: $(PY)
	$(PY) network/run_scenario.py --vehicles $(VEHICLES) --duration $(DURATION) --seed $(SEED) \
	    --backend ns3 --protocol $(PROTOCOL) --attacker-ratio $(ATTACK) --ledger $(LEDGER) --netanim

quick: $(PY)
	$(PY) experiments/run.py --config experiments/configs/quick_real.json --jobs $(JOBS)

compare: $(PY)
	$(PY) experiments/run.py --config experiments/configs/compare_real.json --jobs $(JOBS)

show: $(PY)
	$(PY) experiments/show.py

mock: $(PY)
	@if ss -ltnH "sport = :$(PORT)" 2>/dev/null | grep -q .; then \
	    echo "port $(PORT) is in use; run: make mock PORT=3100"; exit 1; fi
	PORT=$(PORT) $(PY) ledger/mock/mock_ledger_server.py

gateway:
	@if ss -ltnH "sport = :$(PORT)" 2>/dev/null | grep -q .; then \
	    echo "port $(PORT) is in use; run: make gateway PORT=3100"; exit 1; fi
	cd ledger/gateway && PORT=$(PORT) npm start

fabric-up:
	./ledger/start.sh

fabric-down:
	./ledger/network/down.sh

clean-results:
	rm -rf experiments/results
