#!/bin/sh
# Refreshes the vectors from the standard's published copy on sharness.ai into $1 (default: here).
set -e
BASE=https://sharness.ai/code/standards/policy-v0
DIR=${1:-$(dirname "$0")}
mkdir -p "$DIR/vectors"
curl -sSf "$BASE/vectors.json" -o "$DIR/vectors.json"
for f in $(python3 -c "import json,sys; print(' '.join(c['file'] for c in json.load(open(sys.argv[1]))['cases']))" "$DIR/vectors.json" 2>/dev/null || grep -o '"vectors/[^"]*"' "$DIR/vectors.json" | tr -d '"'); do
  curl -sSf "$BASE/$f" -o "$DIR/$f"
done
echo "fetched $(grep -c '"name"' "$DIR/vectors.json") vectors into $DIR"
