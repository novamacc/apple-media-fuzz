#!/bin/bash
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"
echo "=== ImageIO Fuzzer Build ==="
mkdir -p corpus crashes

# Build seed generator if it exists
if [ -f seed_generator.m ]; then
    echo "Building seed generator..."
    clang -framework ImageIO -framework CoreGraphics -framework CoreFoundation -framework CoreServices \
        -O2 -o seed_generator seed_generator.m 2>/dev/null && ./seed_generator corpus/ 2>/dev/null || echo "Seed gen skipped"
fi

# Build fuzzer with standalone main (no libFuzzer needed)
echo "Building fuzzer..."
clang -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
    -framework ImageIO -framework CoreGraphics -framework CoreFoundation -framework CoreServices \
    -o fuzz_imageio standalone_main.c fuzz_imageio.m 2>/dev/null || \
clang -g -O1 -fsanitize=address -fno-omit-frame-pointer \
    -framework ImageIO -framework CoreGraphics -framework CoreFoundation -framework CoreServices \
    -o fuzz_imageio standalone_main.c fuzz_imageio.m

echo "Build complete: $(ls -la fuzz_imageio 2>/dev/null | awk '{print $5}') bytes"
