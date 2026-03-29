# apple-media-fuzz

Continuous fuzzing of Apple media frameworks on macOS using libFuzzer with AddressSanitizer and UndefinedBehaviorSanitizer.

## Fuzzers

| Fuzzer | Target | Formats | Zero-Click Vectors |
|--------|--------|---------|-------------------|
| `imageio_fuzzer` | ImageIO + CoreGraphics | DNG, HEIF, WebP, TIFF, PSD, JP2, EXR, BMP, ICO, GIF, PNG, ICC | iMessage, Mail, Safari, Spotlight |
| `aiff_escalation_fuzzer` | AudioToolbox | AIFF, AIFC, WAV, CAF, MP3, AAC, FLAC, AU, AMR, MIDI | Spotlight, Safari Web Audio, Mail, AirDrop |
| `pdf_fuzzer` | CoreGraphics PDF | PDF (9 paths: JBIG2, streams, scanner, fonts, encryption) | Mail, Spotlight, Safari, QuickLook |
| `transcoder_fuzzer` | IMTranscoderAgent | HEIC/JPEG/PNG/GIF transcoding, resize, ICC conversion | iMessage image processing |

## CI

Runs on `macos-15` every 4 hours via GitHub Actions. Each fuzzer runs for ~5 hours with 3 parallel workers. Crash artifacts are uploaded automatically.

## Local Build

```bash
cd imageio_fuzzer && ./build.sh
./fuzz_imageio corpus/ -max_len=65536 -timeout=10 -jobs=4 -workers=4
```
