#!/usr/bin/env bash
# Download VeReMi Extension (Kamel et al. 2020; combined labelled CSV, Mendeley Data
# DOI 10.17632/k62n4z9gdz.1, 330 MB compressed, 1.2 GB CSV, 3,194,808 messages)
# into detection/data/veremi_ext/mixalldata_clean.csv.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/data/veremi_ext"
URL="https://data.mendeley.com/public-files/datasets/k62n4z9gdz/files/8c817608-1953-4282-8315-337a6859da4c/file_downloaded"
mkdir -p "$DIR"
if [[ -f "$DIR/mixalldata_clean.csv" ]]; then
  echo "VeReMi Extension already at $DIR"
  exit 0
fi
curl -fL -o "$DIR/mixalldata_clean.tar.xz" "$URL"
tar -xJf "$DIR/mixalldata_clean.tar.xz" -C "$DIR"
rm "$DIR/mixalldata_clean.tar.xz"
echo "VeReMi Extension ready: $DIR/mixalldata_clean.csv"
