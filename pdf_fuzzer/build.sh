#!/bin/bash
# build.sh — Build CoreGraphics PDF fuzzer
set -e
cd "$(dirname "$0")"

COMMON="-framework Foundation -framework CoreGraphics -framework CoreFoundation -framework ImageIO"

echo "═══════════════════════════════════════════════"
echo "  CoreGraphics PDF Parser Fuzzer (God-Level)  "
echo "═══════════════════════════════════════════════"
echo ""

echo "[1/3] Building seed generator..."
clang $COMMON -O2 -o seed_pdf seed_pdf.m 2>&1
echo "      Done."

echo "[2/3] Generating seed corpus..."
mkdir -p corpus crashes
./seed_pdf corpus/
echo ""

echo "[3/3] Building fuzzer (ASAN + UBSan + libFuzzer)..."
clang $COMMON \
    -fsanitize=fuzzer,address,undefined \
    -fno-sanitize-recover=undefined \
    -g -O1 \
    -o fuzz_pdf fuzz_pdf.m 2>&1
echo "      Done."

echo ""
echo "═══════════════════════════════════════════════"
echo "  BUILD COMPLETE"
echo "═══════════════════════════════════════════════"
SEED_COUNT=$(ls corpus/ | wc -l | tr -d ' ')
echo "Corpus seeds: $SEED_COUNT files (9 paths)"
echo ""
echo "Run:"
echo "  Quick:     ./fuzz_pdf corpus/ -max_len=65536 -timeout=15 -max_total_time=120 -artifact_prefix=crashes/"
echo "  Overnight: ./fuzz_pdf corpus/ -max_len=131072 -timeout=15 -jobs=8 -workers=4 -artifact_prefix=crashes/"
