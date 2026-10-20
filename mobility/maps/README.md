# Real-city road networks

## `monaco_centre.net.xml` — central Monaco (Monte-Carlo, the port, Monaco-Ville)

1.9 × 2.3 km, 437 junctions, 909 road edges for passenger cars; 27 RSUs at the default 450 m spacing.
Built from the OpenStreetMap export of the MoST scenario
(L. Codecá, J. Härri, "Towards Multimodal Mobility Simulation of C-ITS: The Monaco SUMO Traffic
Scenario", VNC 2017; https://github.com/lcodeca/MoSTScenario, file `tools/most.raw.osm`,
OSM data © OpenStreetMap contributors, ODbL):

```bash
git clone --depth 1 https://github.com/lcodeca/MoSTScenario
python mobility/build_scenario.py --osm MoSTScenario/tools/most.raw.osm \
       --bbox 7.410,43.727,7.433,43.745 --vehicles 60 --duration 120
# writes mobility/nets/most_7.4100_43.7270_7.4330_43.7450.net.xml = this file
```

Use it with `--net mobility/maps/monaco_centre.net.xml` (configs `realmap_*.json`).

## Your own city

Export an area with `python $SUMO_HOME/tools/osmWebWizard.py` (or download an `.osm` from
openstreetmap.org → Export), then `--osm <file>`, and `--bbox minlon,minlat,maxlon,maxlat` to cut
a 1–3 km² centre out of a larger export.
