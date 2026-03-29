#!/bin/bash
# build.sh - Build CoreGraphics PDF fuzzer
# Handles both libFuzzer (local Xcode) and standalone harness (GitHub Actions CI)
set -e
cd "$(dirname "$0")"

COMMON="-framework Foundation -framework CoreGraphics -framework CoreFoundation -framework ImageIO"

echo "=== CoreGraphics PDF Parser Fuzzer ==="
echo ""

echo "[1/3] Building seed generator..."
clang $COMMON -O2 -o seed_pdf seed_pdf.m 2>&1
echo "      Done."

echo "[2/3] Generating seed corpus..."
mkdir -p corpus crashes
./seed_pdf corpus/
echo ""

echo "[3/3] Building fuzzer..."
if echo 'int LLVMFuzzerTestOneInput(const char *d, long s){return 0;}' | clang  -x c - -o /dev/null 2>/dev/null; then
    echo "      libFuzzer available - building with "
    clang $COMMON \
        -fsanitize=address,undefined \
        -fno-sanitize-recover=undefined \
        -g -O1 \
        -o fuzz_pdf fuzz_pdf.m 2>&1
else
    echo "      libFuzzer NOT available - building with standalone harness"
    clang $COMMON \
        -fsanitize=address,undefined \
        -fno-sanitize-recover=undefined \
        -g -O1 \
        -c -o fuzz_pdf.o fuzz_pdf.m
    clang -fsanitize=address,undefined -g -O1 \
        -c -o standalone_harness.o ../standalone_harness.c
    clang $COMMON \
        -fsanitize=address,undefined \
        -g -O1 \
        -o fuzz_pdf fuzz_pdf.o standalone_harness.o
    rm -f fuzz_pdf.o standalone_harness.o
fi
echo "      Done."

echo ""
echo "=== BUILD COMPLETE ==="
SEED_COUNT=$(ls corpus/ | wc -l | tr -d ' ')
echo "Corpus seeds: $SEED_COUNT files (9 paths)"
echo ""
echo "Run:"
echo "  Quick:     ./fuzz_pdf corpus/ -max_len=65536 -timeout=15 -max_total_time=120 -artifact_prefix=crashes/"
echo "  Overnight: ./fuzz_pdf corpus/ -max_len=131072 -timeout=15 -jobs=8 -workers=4 -artifact_prefix=crashes/"
