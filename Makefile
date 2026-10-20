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
PORT     ?= 3100
LEDGER   ?= mock
JOBS     ?= 4

.PHONY: help setup test test-ledger run run-ns3 quick compare compare-v3 ablation-v3 trust-v3 evaluate-v3 evaluate-all compare-lust detector-benchmark detector-model report show mock gateway fabric-up fabric-down ledger-bench clean-results

help:
	@echo "make setup          create .venv and install everything (./setup.sh)"
	@echo "make test           all Python tests"
	@echo "make test-ledger    ledger conformance tests against a running mock (make mock) on PORT"
	@echo "make run            one scenario: VEHICLES=$(VEHICLES) DURATION=$(DURATION) PROTOCOL=$(PROTOCOL) BACKEND=$(BACKEND)"
	@echo "make run-ns3        same, forced onto ns-3, with NetAnim output"
	@echo "make quick          6-run sweep (experiments/configs/quick_real.json), tables and figures"
	@echo "make compare        ours vs stub vs ECDSA PKI vs central authority (compare_real.json)"
	@echo "make compare-v3     ns-3: ECDSA PKI, central TA, Phase I, v2, v2-mac, v3 at 50/100/150 vehicles"
	@echo "make ablation-v3    ns-3: v2 plus each v3 mechanism on its own, 100 vehicles"
	@echo "make trust-v3       ns-3: 2 of 9 RSUs compromised, plain K vs trust-weighted revocation"
	@echo "make evaluate-v3    all three, then report.md in each results folder"
	@echo "make evaluate-all   every v3 experiment incl. LuST and sensitivity (overnight), then the dashboard"
	@echo "make compare-lust   ns-3 on LuST (Luxembourg), 3 times of day (needs mobility/get_lust.sh)"
	@echo "make detector-benchmark  VeReMi Extension benchmark (needs detection/get_veremi.sh)"
	@echo "make detector-model      train the simulator's detector model (--detector-mode hybrid)"
	@echo "make ledger-bench   real Fabric: commit latency of Raft vs BFT ordering (Docker, Fabric 3.1.5)"
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

compare-v3: $(PY)
	$(PY) experiments/run.py --config experiments/configs/compare_v3.json --jobs $(JOBS)
	$(PY) experiments/report.py experiments/results/compare_v3

ablation-v3: $(PY)
	$(PY) experiments/run.py --config experiments/configs/ablation_v3.json --jobs $(JOBS)
	$(PY) experiments/report.py experiments/results/ablation_v3

trust-v3: $(PY)
	$(PY) experiments/run.py --config experiments/configs/trust_v3.json --jobs $(JOBS)
	$(PY) experiments/report.py experiments/results/trust_v3

evaluate-v3: compare-v3 ablation-v3 trust-v3

evaluate-all: $(PY)
	JOBS=$(JOBS) ./experiments/run_all.sh

compare-lust: $(PY)
	$(PY) experiments/run.py --config experiments/configs/compare_lust.json --jobs $(JOBS)
	$(PY) experiments/report.py experiments/results/compare_lust

detector-benchmark: $(PY)
	$(PY) -m detection.benchmark

# simulator detector model (used only by --detector-mode hybrid / the ablation): labelled BSMs
# from grid runs with all six attacks (seeds 11-12, not used by any evaluation), then training
detector-model: $(PY)
	for a in const_pos random_pos const_speed random_speed sudden_stop flood; do for s in 11 12; do \
	  $(PY) network/run_scenario.py --vehicles 100 --duration 120 --seed $$s --backend lite --protocol real \
	    --mobility-step 0.1 --attacker-ratio 0.1 --attack $$a --attack-start 20 --rssi-check --detector-log \
	    --out experiments/results/detector_train/$${a}_s$$s --quiet; done; done
	$(PY) -m detection.train_sim experiments/results/detector_train/*

report: $(PY)
	$(PY) experiments/report.py $(patsubst %/aggregate.csv,%,$(wildcard experiments/results/*/aggregate.csv))

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

ledger-bench:
	PORT=$(PORT) ./ledger/bench/consensus_bench.sh

clean-results:
	rm -rf experiments/results
