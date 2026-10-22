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

.PHONY: help setup test test-ledger run run-ns3 quick compare compare-v3 ablation-v3 trust-v3 evaluate-v3 demo live replay scenarios scenario-low scenario-high scenario-mixed viz emergency report evaluate-all compare-lust detector-benchmark detector-model report show mock gateway fabric-up fabric-down ledger-bench clean-results

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
	@echo "make demo           live side-by-side: Phase I vs v3-fast vs v3-private on ns-3 (~3 min)"
	@echo "make report         the project report PDF (docs/report) from the current results"
	@echo "make emergency      emergency vehicles: login priority, alerts, fake-ambulance attack (LuST)"
	@echo "make live           narrate one ns-3 run in plain English as it runs (PROFILE=..., ALL=1 for every handover)"
	@echo "make viz            the same as a live map in the browser, click vehicles and RSUs (MAP=lust:low ...)"
	@echo "make replay         replay a finished run the same way (RUN=<run folder> SPEED=4)"
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

# the project report (docs/report): tables, figures and numbers from the results, then the PDF
# with latexmk or tectonic if one is installed (else upload docs/report to Overleaf)
report: $(PY)
	$(PY) experiments/thesis_data.py
	cd docs/report && if command -v latexmk >/dev/null; then latexmk -pdf -interaction=nonstopmode report.tex; \
	elif command -v tectonic >/dev/null; then tectonic -X compile report.tex; \
	else echo "no LaTeX found: upload docs/report to Overleaf, or install latexmk or tectonic"; fi

# emergency vehicles on LuST mid-day and rush hour: login priority, alerts, fake-ambulance attack
emergency: $(PY)
	$(PY) experiments/run.py --config experiments/configs/emergency.json --jobs $(JOBS)
	$(PY) experiments/report.py experiments/results/emergency

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

# a live side-by-side for a presentation: Phase I design vs v3-fast on ns-3 (~3 min).
# make demo / make live settings, e.g. make live CARS=100 SIM_TIME=300 RSU_SPACING=333 PACE=1
CARS        ?= 50          # vehicles (ignored with MAP=lust:...)
SIM_TIME    ?= 60          # simulated seconds
RSU_SPACING ?= 450         # m between RSUs; on the 1 km grid 1000 -> 4 RSUs, 450 -> 9, 333 -> 16, 250 -> 25
ATTACKERS   ?= 0.1         # share of vehicles that attack
ATTACK_TYPE ?= random_pos  # const_pos, random_pos, const_speed, random_speed, sudden_stop, flood
ATTACK_AT   ?= 20          # s when the attack starts
MAP         ?= grid        # grid, or real Luxembourg traffic: lust:low, lust:mid, lust:peak
EMERGENCY   ?= 0           # share of honest vehicles that are emergency vehicles (e.g. 0.05)
EV_PRIORITY ?=             # EV_PRIORITY=1: RSUs verify emergency logins ahead of their queue
PACE        ?= 0           # make live: simulated s per wall s (1 = real time, 0 = as fast as possible)
ALL         ?=             # make live ALL=1: also every handover, renewal, pseudonym change, ledger write
DEMO = $(PY) network/run_scenario.py --vehicles $(strip $(CARS)) --duration $(strip $(SIM_TIME)) --seed $(SEED) \
	--backend $(BACKEND) --protocol real --mobility-step 0.1 --rsu-spacing $(strip $(RSU_SPACING)) \
	--attacker-ratio $(strip $(ATTACKERS)) --attack $(strip $(ATTACK_TYPE)) --attack-start $(strip $(ATTACK_AT)) \
	$(if $(filter grid,$(strip $(MAP))),,--real $(strip $(MAP))) --rsu-cpu --v2v-verify \
	$(if $(filter-out 0,$(strip $(EMERGENCY))),--emergency-ratio $(strip $(EMERGENCY))) \
	$(if $(strip $(EV_PRIORITY)),--emergency-priority) \
	--privacy-log --compute-times experiments/compute_times_v3.json
demo: $(PY)
	$(DEMO) --out experiments/results/demo/Phase-I
	$(DEMO) --profile v3-fast --out experiments/results/demo/v3-fast
	$(DEMO) --profile v3-private --out experiments/results/demo/v3-private
	$(PY) experiments/show.py experiments/results/demo/Phase-I experiments/results/demo/v3-fast experiments/results/demo/v3-private

# narrate one ns-3 run in plain English while it runs: who joins, the attack, detection, the
# blockchain revocation, the attacker shut out (PROFILE=Phase-I for the original design)
PROFILE ?= v3-fast
live: $(PY)
	$(DEMO) $(if $(filter Phase-I,$(PROFILE)),,--profile $(PROFILE)) --live --live-pace $(strip $(PACE)) $(if $(strip $(ALL)),--live-all) --out experiments/results/live/$(PROFILE)

# the same run as a live map in the browser (http://127.0.0.1:8765): click a vehicle or RSU for its
# details; pause and speed on the page (PACE sets the starting speed, 1 = real time)
VIZ_PORT ?= 8765
viz: $(PY)
	@if ss -ltnH "sport = :$(VIZ_PORT)" 2>/dev/null | grep -q .; then \
	    echo "port $(VIZ_PORT) is in use (another make viz?); run: make viz VIZ_PORT=8766"; exit 1; fi
	$(DEMO) $(if $(filter Phase-I,$(PROFILE)),,--profile $(PROFILE)) --viz --viz-port $(VIZ_PORT) \
	    --live-pace $(if $(filter 0,$(strip $(PACE))),1,$(strip $(PACE))) --out experiments/results/viz/$(PROFILE)

# replay a finished run the same way, without simulating (RUN=<run folder>, SPEED=sim s per s)
RUN ?= experiments/results/demo/v3-fast
SPEED ?= 4
replay: $(PY)
	$(PY) experiments/live.py $(RUN) --speed $(SPEED)

# three demo scenarios on the grid (ns-3, this work), each recorded with a NetAnim file in which
# normal vehicles are blue, attackers red, emergency vehicles orange and RSUs grey:
#   make scenarios            record all three (experiments/results/scenarios/, ~4 min)
#   make scenario-low         30 vehicles, live map + narration (http://127.0.0.1:8765)
#   make scenario-high        150 vehicles, live
#   make scenario-mixed       60 vehicles with 10 % attackers and 10 % emergency vehicles, live
SCN = $(PY) network/run_scenario.py --seed 1 --backend ns3 --protocol real --mobility-step 0.1 \
	--rsu-spacing 450 --attacker-ratio 0.1 --attack random_pos --rsu-cpu --v2v-verify --privacy-log \
	--compute-times experiments/compute_times_v3.json --profile v3-fast
SCN_LOW   = --vehicles 30 --duration 120 --attack-start 40
SCN_HIGH  = --vehicles 150 --duration 90 --attack-start 30
SCN_MIXED = --vehicles 60 --duration 120 --attack-start 40 --emergency-ratio 0.1 --emergency-priority
SCN_LIVE  = --live --live-pace 1 --viz --viz-port $(VIZ_PORT)
scenarios: $(PY)
	$(SCN) $(SCN_LOW) --netanim --live --out experiments/results/scenarios/1_low_density 2>/dev/null > experiments/results/scenarios/1_low_density.log
	$(SCN) $(SCN_HIGH) --netanim --live --out experiments/results/scenarios/2_high_density 2>/dev/null > experiments/results/scenarios/2_high_density.log
	$(SCN) $(SCN_MIXED) --netanim --live --out experiments/results/scenarios/3_all_node_types 2>/dev/null > experiments/results/scenarios/3_all_node_types.log
scenario-low: $(PY)
	$(SCN) $(SCN_LOW) $(SCN_LIVE) --out experiments/results/viz/scenario_low 2>/dev/null
scenario-high: $(PY)
	$(SCN) $(SCN_HIGH) $(SCN_LIVE) --out experiments/results/viz/scenario_high 2>/dev/null
scenario-mixed: $(PY)
	$(SCN) $(SCN_MIXED) $(SCN_LIVE) --out experiments/results/viz/scenario_mixed 2>/dev/null

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
