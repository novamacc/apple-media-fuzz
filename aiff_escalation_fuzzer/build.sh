#!/bin/bash
# build_audio.sh — Build the god-level AudioToolbox multi-format fuzzer
set -e
cd "$(dirname "$0")"

COMMON="-framework AudioToolbox -framework CoreFoundation -framework Foundation"

echo "=== AudioToolbox Multi-Format Fuzzer ==="
echo ""

echo "[1/3] Building seed generator..."
clang $COMMON -O2 -o seed_audio seed_audio.m 2>&1
echo "      Done."

echo "[2/3] Generating seed corpus..."
mkdir -p corpus_audio crashes_audio
./seed_audio corpus_audio/
# Copy existing AIFF seeds too
cp corpus/FINAL_POC_821bytes.aiff corpus_audio/ 2>/dev/null || true
cp corpus/minimized_poc_v2.aiff corpus_audio/ 2>/dev/null || true
echo ""

echo "[3/3] Building fuzzer (ASAN + UBSan + libFuzzer)..."
clang $COMMON \
    -fsanitize=fuzzer,address,undefined \
    -fno-sanitize-recover=undefined \
    -g -O1 \
    -o fuzz_audio fuzz_audio.m 2>&1
echo "      Done."

echo ""
echo "=== BUILD COMPLETE ==="
SEED_COUNT=$(ls corpus_audio/ | wc -l | tr -d ' ')
echo "Corpus seeds: $SEED_COUNT files (10 formats)"
echo ""
echo "Run:"
echo "  Quick:     ./fuzz_audio corpus_audio/ -max_len=65536 -timeout=5 -max_total_time=60 -artifact_prefix=crashes_audio/"
echo "  Overnight: ./fuzz_audio corpus_audio/ -max_len=65536 -timeout=5 -jobs=8 -workers=4 -artifact_prefix=crashes_audio/"
