#!/bin/bash
#
# build.sh — Build the ImageIO fuzzer suite
#
# Usage:
#   ./build.sh              # Build everything
#   ./build.sh fuzz         # Build + start 60-second fuzzing run
#   ./build.sh overnight    # Build + start long fuzzing run (4 workers)
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

# Step 3: Build fuzzer with ASAN + UBSan
echo "[3/3] Building fuzzer (ASAN + UBSan + libFuzzer)..."
clang $COMMON_FLAGS \
    -fsanitize=fuzzer,address,undefined \
    -fno-sanitize-recover=undefined \
    -g -O1 \
    -o fuzz_imageio fuzz_imageio.m
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
echo "  DNG-focused:          ./fuzz_imageio corpus/ -max_len=65536 -timeout=10 -only_ascii=0"
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
