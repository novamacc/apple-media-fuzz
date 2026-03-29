#!/bin/bash
# build.sh - Build IMTranscoderAgent fuzzer
# Handles both libFuzzer (local Xcode) and standalone harness (GitHub Actions CI)
set -e
cd "$(dirname "$0")"

COMMON="-framework Foundation -framework ImageIO -framework CoreGraphics -framework CoreFoundation -framework CoreImage"

echo "=== IMTranscoderAgent Fuzzer ==="
echo ""

echo "[1/2] Creating seed corpus..."
mkdir -p corpus crashes
# Create minimal seed files using built-in image generation
cat > /tmp/gen_transcoder_seeds.m << 'SEEDEOF'
#import <Foundation/Foundation.h>
#import <ImageIO/ImageIO.h>
#import <CoreGraphics/CoreGraphics.h>
#include <sys/stat.h>

int main(int argc, char *argv[]) {
    const char *dir = argc > 1 ? argv[1] : "corpus";
    mkdir(dir, 0755);
    int w = 8, h = 8;
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGContextRef ctx = CGBitmapContextCreate(NULL, w, h, 8, w*4, cs, kCGImageAlphaPremultipliedLast);
    CGContextSetRGBFillColor(ctx, 1, 0, 0, 1);
    CGContextFillRect(ctx, CGRectMake(0,0,w,h));
    CGImageRef img = CGBitmapContextCreateImage(ctx);
    NSString *types[] = {@"public.png", @"public.jpeg", @"public.tiff", @"com.compuserve.gif"};
    NSString *exts[] = {@"png", @"jpg", @"tiff", @"gif"};
    for (int i = 0; i < 4; i++) {
        CFMutableDataRef d = CFDataCreateMutable(NULL, 0);
        CGImageDestinationRef dst = CGImageDestinationCreateWithData(d, (__bridge CFStringRef)types[i], 1, NULL);
        if (dst) {
            CGImageDestinationAddImage(dst, img, NULL);
            CGImageDestinationFinalize(dst);
            NSString *path = [NSString stringWithFormat:@"%s/seed_%@.%@", dir, exts[i], exts[i]];
            [(__bridge NSData *)d writeToFile:path atomically:YES];
            CFRelease(dst);
        }
        CFRelease(d);
    }
    CGImageRelease(img); CGContextRelease(ctx); CGColorSpaceRelease(cs);
    printf("[+] Transcoder seeds generated\n");
    return 0;
}
SEEDEOF
clang -framework Foundation -framework ImageIO -framework CoreGraphics -O2 -o /tmp/gen_tc_seeds /tmp/gen_transcoder_seeds.m 2>&1
/tmp/gen_tc_seeds corpus/
rm -f /tmp/gen_tc_seeds /tmp/gen_transcoder_seeds.m
echo "      Done."

echo "[2/2] Building fuzzer..."
if echo 'int LLVMFuzzerTestOneInput(const char *d, long s){return 0;}' | clang -fsanitize=fuzzer -x c - -o /dev/null 2>/dev/null; then
    echo "      libFuzzer available - building with -fsanitize=fuzzer"
    clang $COMMON \
        -fsanitize=fuzzer,address,undefined \
        -fno-sanitize-recover=undefined \
        -g -O1 \
        -o fuzz_transcoder fuzz_transcoder.m 2>&1
else
    echo "      libFuzzer NOT available - building with standalone harness"
    clang $COMMON \
        -fsanitize=address,undefined \
        -fno-sanitize-recover=undefined \
        -g -O1 \
        -c -o fuzz_transcoder.o fuzz_transcoder.m
    clang -fsanitize=address,undefined -g -O1 \
        -c -o standalone_harness.o ../standalone_harness.c
    clang $COMMON \
        -fsanitize=address,undefined \
        -g -O1 \
        -o fuzz_transcoder fuzz_transcoder.o standalone_harness.o
    rm -f fuzz_transcoder.o standalone_harness.o
fi
echo "      Done."

echo ""
echo "=== BUILD COMPLETE ==="
echo "Corpus seeds: $(ls corpus/ | wc -l | tr -d ' ') files"
echo "Run: ./fuzz_transcoder corpus/ -max_len=65536 -timeout=10 -artifact_prefix=crashes/"
