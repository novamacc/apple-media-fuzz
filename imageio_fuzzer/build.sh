#!/bin/bash
#
# build.sh - Build the ImageIO fuzzer suite
#
# Handles both libFuzzer (local Xcode) and standalone harness (GitHub Actions CI)
#
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

COMMON_FLAGS="-framework ImageIO -framework CoreGraphics -framework CoreFoundation -framework CoreServices"

echo "=== ImageIO Zero-Click Fuzzer ==="
echo ""

# Step 1: Build seed generator
echo "[1/3] Building seed generator..."
clang $COMMON_FLAGS -O2 -o seed_generator seed_generator.m
echo "      Done."

# Step 2: Generate seed corpus
echo "[2/3] Generating seed corpus..."
mkdir -p corpus crashes
./seed_generator corpus/
echo ""

# Step 3: Detect libFuzzer availability and build
echo "[3/3] Building fuzzer..."

if echo 'int LLVMFuzzerTestOneInput(const char *d, long s){return 0;}' | clang -fsanitize=fuzzer -x c - -o /dev/null 2>/dev/null; then
    echo "      libFuzzer available - building with -fsanitize=fuzzer"
    clang $COMMON_FLAGS \
        -fsanitize=fuzzer,address,undefined \
        -fno-sanitize-recover=undefined \
        -g -O1 \
        -o fuzz_imageio fuzz_imageio.m
else
    echo "      libFuzzer NOT available - building with standalone harness"
    # Compile fuzz target as object (no main)
    clang $COMMON_FLAGS \
        -fsanitize=address,undefined \
        -fno-sanitize-recover=undefined \
        -g -O1 \
        -c -o fuzz_imageio.o fuzz_imageio.m
    # Compile standalone harness
    clang -fsanitize=address,undefined -g -O1 \
        -c -o standalone_harness.o ../standalone_harness.c
    # Link together
    clang $COMMON_FLAGS \
        -fsanitize=address,undefined \
        -g -O1 \
        -o fuzz_imageio fuzz_imageio.o standalone_harness.o
    rm -f fuzz_imageio.o standalone_harness.o
fi
echo "      Done."

echo ""
echo "=== BUILD COMPLETE ==="
echo ""
echo "Corpus seeds: $(ls corpus/ | wc -l | tr -d ' ') files"
echo ""
echo "Run commands:"
echo "  Quick test (60s):     ./fuzz_imageio corpus/ -max_len=65536 -timeout=10 -max_total_time=60"
echo "  Parallel (4 workers): ./fuzz_imageio corpus/ -max_len=65536 -timeout=10 -jobs=4 -workers=4"
echo "  Overnight:            ./fuzz_imageio corpus/ -max_len=65536 -timeout=10 -jobs=8 -workers=4 -print_final_stats=1"
echo ""
echo "Crashes saved to: $DIR/crashes/"
echo ""

# Optional: auto-run based on argument
if [ "$1" = "fuzz" ]; then
    echo "=== Starting 60-second fuzzing run ==="
    ./fuzz_imageio corpus/ \
        -max_len=65536 \
        -timeout=10 \
        -max_total_time=60 \
        -print_final_stats=1 \
        -artifact_prefix=crashes/
elif [ "$1" = "overnight" ]; then
    echo "=== Starting overnight fuzzing run (4 workers) ==="
    ./fuzz_imageio corpus/ \
        -max_len=65536 \
        -timeout=10 \
        -jobs=8 \
        -workers=4 \
        -print_final_stats=1 \
        -artifact_prefix=crashes/
fi
