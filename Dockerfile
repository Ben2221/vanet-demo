# Reproducible Linux environment with SUMO and ns-3 Python bindings.
# Useful on Windows/macOS, where ns-3's Python bindings do not install natively.
#
#   docker build -t vanet-demo .
#   docker run --rm -it -v "$PWD:/work" vanet-demo python network/run_scenario.py --backend ns3
#
# The ns3 wheel needs cppyy, whose backend compiles from source: the first
# build takes a while and needs ~4 GB of RAM.
# The full (non-slim) image already ships g++ and make.
FROM python:3.11

ENV MAKEFLAGS=-j2 CMAKE_BUILD_PARALLEL_LEVEL=2 \
    PIP_DEFAULT_TIMEOUT=300 PIP_RETRIES=10

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && pip install --no-cache-dir ns3

WORKDIR /work
