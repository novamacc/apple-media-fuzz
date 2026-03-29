#!/bin/bash
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"
echo "=== Building fuzz_audio ==="
mkdir -p corpus crashes

# Build seed generator if exists
if [ -f seed_generator.m ]; then
    clang -framework Foundation -framework CoreFoundation -framework AudioToolbox -O2 -o seed_generator seed_generator.m 2>/dev/null && ./seed_generator corpus/ 2>/dev/null || echo "Seed gen skipped"
fi

# Build with standalone main + ASAN
clang -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer     -framework Foundation -framework CoreFoundation -framework AudioToolbox     -o fuzz_audio standalone_main.c fuzz_audio.m 2>/dev/null || clang -g -O1 -fsanitize=address -fno-omit-frame-pointer     -framework Foundation -framework CoreFoundation -framework AudioToolbox     -o fuzz_audio standalone_main.c fuzz_audio.m
echo "Build complete: $(ls -la fuzz_audio 2>/dev/null | awk '{print $5}') bytes"
