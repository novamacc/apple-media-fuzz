/*
 * fuzz_imageio.m — God-Level Coverage-Guided ImageIO Fuzzer
 *
 * Targets the EXACT attack surface that produced:
 *   - FORCEDENTRY ($0-day, NSO, 2021): JBIG2 in CoreGraphics PDF via ImageIO
 *   - CVE-2025-43300 ($0-day, 2025): OOB write in ImageIO DNG decoder
 *   - CVE-2023-4863 ($0-day, 2023): WebP heap overflow via ImageIO
 *
 * ARCHITECTURE:
 *   This harness exercises FIVE distinct parsing paths in ImageIO,
 *   because each path uses different internal code:
 *
 *   Path 1: CGImageSourceCreateWithData → full decode to bitmap
 *           (deepest parsing — decodes all pixel data)
 *   Path 2: CGImageSourceCreateThumbnailAtIndex
 *           (iMessage preview generation — separate rescaling code)
 *   Path 3: CGImageSourceCopyPropertiesAtIndex
 *           (metadata extraction — EXIF/IPTC/XMP parsing, ICC profiles)
 *   Path 4: CGImageSourceCreateIncremental + UpdateData
 *           (STREAMING parse — how iMessage receives images incrementally)
 *   Path 5: CGColorSpaceCreateWithICCData
 *           (ICC profile parsing — embedded in all image formats)
 *
 * FORMAT TARGETING:
 *   The first 2 bytes of fuzz input select the format hint:
 *     0x00-0x1F: DNG  (RAW camera — CVE-2025-43300 class)
 *     0x20-0x3F: HEIF (Apple's codec — complex container)
 *     0x40-0x5F: WebP (libwebp — CVE-2023-4863 class)
 *     0x60-0x7F: TIFF (ancient — many historical CVEs)
 *     0x80-0x8F: PSD  (FORCEDENTRY delivery format)
 *     0x90-0x9F: JP2  (JPEG2000 — wavelet compression)
 *     0xA0-0xAF: OpenEXR (HDR — float math bugs)
 *     0xB0-0xBF: BMP  (simple but parser edge cases)
 *     0xC0-0xCF: ICO  (multi-image container)
 *     0xD0-0xDF: GIF  (animation — state machine)
 *     0xE0-0xEF: PNG  (deflate + filter prediction)
 *     0xF0-0xFF: No hint (let ImageIO auto-detect — tests format detection)
 *
 *   The 3rd byte selects which parsing PATH to exercise.
 *   The 4th byte selects incremental chunk size strategy.
 *
 * Build:
 *   clang -framework ImageIO -framework CoreGraphics -framework CoreFoundation \
 *         -framework CoreServices \
 *         -fsanitize=fuzzer,address,undefined -g -O1 \
 *         -o fuzz_imageio fuzz_imageio.m
 *
 * Run:
 *   ./fuzz_imageio corpus/ -max_len=65536 -timeout=10 -jobs=4 -workers=4
 *
 * Author: pavan0x01
 * Date:   2026-03-29
 */

#import <ImageIO/ImageIO.h>
#import <CoreGraphics/CoreGraphics.h>
#import <CoreFoundation/CoreFoundation.h>
#import <CoreServices/CoreServices.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ================================================================
 * Format magic headers — prepended to fuzz data to ensure ImageIO
 * recognizes the format and enters the target parser.
 * Without these, ImageIO would reject most inputs at the format
 * detection stage, and we'd never reach the deep parsing code.
 * ================================================================ */

/* TIFF (little-endian) */
static const uint8_t TIFF_HEADER[] = {
    0x49, 0x49, 0x2A, 0x00,  /* "II" + TIFF magic (LE) */
    0x08, 0x00, 0x00, 0x00,  /* Offset to first IFD */
};

/* TIFF (big-endian) — DNG uses this */
static const uint8_t TIFF_BE_HEADER[] = {
    0x4D, 0x4D, 0x00, 0x2A,  /* "MM" + TIFF magic (BE) */
    0x00, 0x00, 0x00, 0x08,  /* Offset to first IFD */
};

/* DNG is TIFF-based with specific IFD tags. We use a minimal DNG
 * structure that ImageIO will recognize as DNG (SubIFD with
 * DNGVersion tag 0xC612) */
static const uint8_t DNG_HEADER[] = {
    0x4D, 0x4D, 0x00, 0x2A,  /* "MM" + TIFF magic (BE) */
    0x00, 0x00, 0x00, 0x08,  /* Offset to first IFD = 8 */
    /* IFD at offset 8 */
    0x00, 0x03,              /* 3 IFD entries */
    /* Entry 0: ImageWidth (tag=0x0100, type=SHORT=3, count=1) */
    0x01, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x40, 0x00, 0x00,
    /* Entry 1: ImageLength (tag=0x0101, type=SHORT=3, count=1) */
    0x01, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x30, 0x00, 0x00,
    /* Entry 2: DNGVersion (tag=0xC612, type=BYTE=1, count=4) */
    0xC6, 0x12, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x01, 0x04, 0x00, 0x00,
    /* Next IFD offset = 0 (no more IFDs) */
    0x00, 0x00, 0x00, 0x00,
};

/* HEIF/HEIC (ISO BMFF container with 'ftyp' box) */
static const uint8_t HEIF_HEADER[] = {
    0x00, 0x00, 0x00, 0x1C,  /* Box size: 28 bytes */
    0x66, 0x74, 0x79, 0x70,  /* Box type: "ftyp" */
    0x68, 0x65, 0x69, 0x63,  /* Major brand: "heic" */
    0x00, 0x00, 0x00, 0x00,  /* Minor version */
    0x68, 0x65, 0x69, 0x63,  /* Compatible: "heic" */
    0x68, 0x65, 0x69, 0x78,  /* Compatible: "heix" */
    0x6D, 0x69, 0x66, 0x31,  /* Compatible: "mif1" */
};

/* WebP (RIFF container) */
static const uint8_t WEBP_HEADER[] = {
    0x52, 0x49, 0x46, 0x46,  /* "RIFF" */
    0x00, 0x10, 0x00, 0x00,  /* File size (placeholder) */
    0x57, 0x45, 0x42, 0x50,  /* "WEBP" */
    0x56, 0x50, 0x38, 0x20,  /* "VP8 " chunk (lossy) */
    0x00, 0x08, 0x00, 0x00,  /* Chunk size */
};

/* PSD (Adobe Photoshop — FORCEDENTRY used this) */
static const uint8_t PSD_HEADER[] = {
    0x38, 0x42, 0x50, 0x53,  /* Signature: "8BPS" */
    0x00, 0x01,              /* Version: 1 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Reserved */
    0x00, 0x03,              /* Channels: 3 (RGB) */
    0x00, 0x00, 0x00, 0x20,  /* Height: 32 */
    0x00, 0x00, 0x00, 0x20,  /* Width: 32 */
    0x00, 0x08,              /* Depth: 8 bits */
    0x00, 0x03,              /* Color mode: RGB */
};

/* JPEG2000 */
static const uint8_t JP2_HEADER[] = {
    0x00, 0x00, 0x00, 0x0C,  /* Box length */
    0x6A, 0x50, 0x20, 0x20,  /* JP2 signature box "jP  " */
    0x0D, 0x0A, 0x87, 0x0A,  /* JP2 signature bytes */
};

/* OpenEXR */
static const uint8_t EXR_HEADER[] = {
    0x76, 0x2F, 0x31, 0x01,  /* Magic number */
    0x02, 0x00, 0x00, 0x00,  /* Version 2, single-part */
};

/* BMP */
static const uint8_t BMP_HEADER[] = {
    0x42, 0x4D,              /* "BM" */
    0x36, 0x04, 0x00, 0x00,  /* File size */
    0x00, 0x00, 0x00, 0x00,  /* Reserved */
    0x36, 0x00, 0x00, 0x00,  /* Pixel data offset */
    /* DIB header (BITMAPINFOHEADER) */
    0x28, 0x00, 0x00, 0x00,  /* Header size: 40 */
    0x10, 0x00, 0x00, 0x00,  /* Width: 16 */
    0x10, 0x00, 0x00, 0x00,  /* Height: 16 */
    0x01, 0x00,              /* Planes: 1 */
    0x18, 0x00,              /* Bits per pixel: 24 */
    0x00, 0x00, 0x00, 0x00,  /* Compression: none */
};

/* ICO */
static const uint8_t ICO_HEADER[] = {
    0x00, 0x00,              /* Reserved */
    0x01, 0x00,              /* Type: 1 (icon) */
    0x01, 0x00,              /* Count: 1 image */
    /* ICONDIRENTRY */
    0x10,                    /* Width: 16 */
    0x10,                    /* Height: 16 */
    0x00,                    /* Color count: 0 (>256) */
    0x00,                    /* Reserved */
    0x01, 0x00,              /* Color planes */
    0x20, 0x00,              /* Bits per pixel: 32 */
    0x00, 0x04, 0x00, 0x00,  /* Image size */
    0x16, 0x00, 0x00, 0x00,  /* Offset to image */
};

/* GIF89a */
static const uint8_t GIF_HEADER[] = {
    0x47, 0x49, 0x46, 0x38, 0x39, 0x61,  /* "GIF89a" */
    0x10, 0x00,              /* Width: 16 */
    0x10, 0x00,              /* Height: 16 */
    0x80,                    /* GCT flag + color res + sort + GCT size */
    0x00,                    /* Background color index */
    0x00,                    /* Pixel aspect ratio */
    /* Global Color Table (2 entries × 3 bytes) */
    0x00, 0x00, 0x00,        /* Color 0: black */
    0xFF, 0xFF, 0xFF,        /* Color 1: white */
};

/* PNG */
static const uint8_t PNG_HEADER[] = {
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,  /* PNG signature */
    /* IHDR chunk */
    0x00, 0x00, 0x00, 0x0D,  /* Length: 13 */
    0x49, 0x48, 0x44, 0x52,  /* "IHDR" */
    0x00, 0x00, 0x00, 0x10,  /* Width: 16 */
    0x00, 0x00, 0x00, 0x10,  /* Height: 16 */
    0x08,                    /* Bit depth: 8 */
    0x02,                    /* Color type: RGB */
    0x00,                    /* Compression */
    0x00,                    /* Filter */
    0x00,                    /* Interlace */
    0x00, 0x00, 0x00, 0x00,  /* CRC (will be wrong but that's fine) */
};

/* ICC Profile header (for direct ICC fuzzing) */
static const uint8_t ICC_HEADER[] = {
    0x00, 0x00, 0x01, 0x00,  /* Profile size (256 bytes — lies) */
    0x00, 0x00, 0x00, 0x00,  /* CMM Type */
    0x02, 0x10, 0x00, 0x00,  /* Version 2.1 */
    0x6D, 0x6E, 0x74, 0x72,  /* Device class: "mntr" (monitor) */
    0x52, 0x47, 0x42, 0x20,  /* Color space: "RGB " */
    0x58, 0x59, 0x5A, 0x20,  /* PCS: "XYZ " */
};

/* ================================================================
 * Format selector — maps first byte to header + type hint
 * ================================================================ */
typedef struct {
    const uint8_t *header;
    size_t header_len;
    CFStringRef type_hint;  /* UTType hint for CGImageSource */
} FormatSpec;

static FormatSpec get_format(uint8_t selector) {
    FormatSpec spec = {0};

    if (selector < 0x20) {
        /* DNG — the #1 target */
        spec.header = DNG_HEADER;
        spec.header_len = sizeof(DNG_HEADER);
        spec.type_hint = CFSTR("com.adobe.raw-image");
    } else if (selector < 0x40) {
        /* HEIF/HEIC */
        spec.header = HEIF_HEADER;
        spec.header_len = sizeof(HEIF_HEADER);
        spec.type_hint = CFSTR("public.heic");
    } else if (selector < 0x60) {
        /* WebP */
        spec.header = WEBP_HEADER;
        spec.header_len = sizeof(WEBP_HEADER);
        spec.type_hint = CFSTR("org.webmproject.webp");
    } else if (selector < 0x80) {
        /* TIFF */
        spec.header = (selector & 1) ? TIFF_BE_HEADER : TIFF_HEADER;
        spec.header_len = (selector & 1) ? sizeof(TIFF_BE_HEADER) : sizeof(TIFF_HEADER);
        spec.type_hint = CFSTR("public.tiff");
    } else if (selector < 0x90) {
        /* PSD */
        spec.header = PSD_HEADER;
        spec.header_len = sizeof(PSD_HEADER);
        spec.type_hint = CFSTR("com.adobe.photoshop-image");
    } else if (selector < 0xA0) {
        /* JPEG2000 */
        spec.header = JP2_HEADER;
        spec.header_len = sizeof(JP2_HEADER);
        spec.type_hint = CFSTR("public.jpeg-2000");
    } else if (selector < 0xB0) {
        /* OpenEXR */
        spec.header = EXR_HEADER;
        spec.header_len = sizeof(EXR_HEADER);
        spec.type_hint = CFSTR("com.ilm.openexr-image");
    } else if (selector < 0xC0) {
        /* BMP */
        spec.header = BMP_HEADER;
        spec.header_len = sizeof(BMP_HEADER);
        spec.type_hint = CFSTR("com.microsoft.bmp");
    } else if (selector < 0xD0) {
        /* ICO */
        spec.header = ICO_HEADER;
        spec.header_len = sizeof(ICO_HEADER);
        spec.type_hint = CFSTR("com.microsoft.ico");
    } else if (selector < 0xE0) {
        /* GIF */
        spec.header = GIF_HEADER;
        spec.header_len = sizeof(GIF_HEADER);
        spec.type_hint = CFSTR("com.compuserve.gif");
    } else if (selector < 0xF0) {
        /* PNG */
        spec.header = PNG_HEADER;
        spec.header_len = sizeof(PNG_HEADER);
        spec.type_hint = CFSTR("public.png");
    } else {
        /* No hint — test format auto-detection */
        spec.header = NULL;
        spec.header_len = 0;
        spec.type_hint = NULL;
    }

    return spec;
}

/* ================================================================
 * PATH 1: Full decode to bitmap
 * The deepest parsing path — decodes all pixel data and
 * renders to a bitmap context. This exercises:
 *   - Format header parsing
 *   - Decompression (zlib, LZMA, wavelet, etc.)
 *   - Color space conversion
 *   - ICC profile application
 *   - Alpha premultiplication
 * ================================================================ */
static void path_full_decode(CFDataRef data, CFDictionaryRef options) {
    CGImageSourceRef src = CGImageSourceCreateWithData(data, options);
    if (!src) return;

    size_t count = CGImageSourceGetCount(src);
    /* Limit to 4 frames to avoid animation bombs */
    if (count > 4) count = 4;

    for (size_t i = 0; i < count; i++) {
        CGImageRef img = CGImageSourceCreateImageAtIndex(src, i, options);
        if (!img) continue;

        size_t w = CGImageGetWidth(img);
        size_t h = CGImageGetHeight(img);

        /* Cap dimensions to prevent OOM */
        if (w > 4096 || h > 4096 || w * h > 4 * 1024 * 1024) {
            CGImageRelease(img);
            continue;
        }

        /* Force full decode by drawing to bitmap context */
        if (w > 0 && h > 0) {
            CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
            CGContextRef ctx = CGBitmapContextCreate(
                NULL, w, h, 8, w * 4, cs,
                kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big);

            if (ctx) {
                CGContextDrawImage(ctx, CGRectMake(0, 0, w, h), img);

                /* Read a pixel to force any lazy evaluation */
                uint8_t *pixels = CGBitmapContextGetData(ctx);
                if (pixels) {
                    volatile uint8_t sink = pixels[0];
                    (void)sink;
                }

                CGContextRelease(ctx);
            }
            CGColorSpaceRelease(cs);
        }

        CGImageRelease(img);
    }

    CFRelease(src);
}

/* ================================================================
 * PATH 2: Thumbnail generation
 * This is what iMessage uses to create preview thumbnails.
 * Uses DIFFERENT code paths than full decode — the thumbnail
 * generator has its own rescaling and subsampling logic.
 * ================================================================ */
static void path_thumbnail(CFDataRef data, CFDictionaryRef options) {
    CGImageSourceRef src = CGImageSourceCreateWithData(data, options);
    if (!src) return;

    /* Create options for thumbnail generation */
    CFMutableDictionaryRef thumb_opts = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);

    /* Various thumbnail sizes to exercise different subsampling paths */
    int sizes[] = {64, 128, 256, 1024};
    for (int s = 0; s < 4; s++) {
        CFNumberRef maxSize = CFNumberCreate(
            kCFAllocatorDefault, kCFNumberIntType, &sizes[s]);
        CFDictionarySetValue(thumb_opts,
            kCGImageSourceThumbnailMaxPixelSize, maxSize);
        CFDictionarySetValue(thumb_opts,
            kCGImageSourceCreateThumbnailFromImageAlways,
            kCFBooleanTrue);
        CFDictionarySetValue(thumb_opts,
            kCGImageSourceCreateThumbnailWithTransform,
            kCFBooleanTrue);

        CGImageRef thumb = CGImageSourceCreateThumbnailAtIndex(
            src, 0, thumb_opts);
        if (thumb) {
            /* Force decode */
            size_t w = CGImageGetWidth(thumb);
            size_t h = CGImageGetHeight(thumb);
            if (w > 0 && h > 0 && w <= 4096 && h <= 4096) {
                CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
                CGContextRef ctx = CGBitmapContextCreate(
                    NULL, w, h, 8, w * 4, cs,
                    kCGImageAlphaPremultipliedLast);
                if (ctx) {
                    CGContextDrawImage(ctx, CGRectMake(0, 0, w, h), thumb);
                    CGContextRelease(ctx);
                }
                CGColorSpaceRelease(cs);
            }
            CGImageRelease(thumb);
        }
        CFRelease(maxSize);
    }

    CFRelease(thumb_opts);
    CFRelease(src);
}

/* ================================================================
 * PATH 3: Metadata extraction
 * Parses EXIF, IPTC, XMP, GPS, TIFF tags, Maker Notes, ICC
 * profiles, and Apple-specific metadata. This is a SEPARATE parser
 * from the pixel decoder — metadata parsing bugs are a major class.
 * ================================================================ */
static void path_metadata(CFDataRef data, CFDictionaryRef options) {
    CGImageSourceRef src = CGImageSourceCreateWithData(data, options);
    if (!src) return;

    /* Global properties (file-level metadata) */
    CFDictionaryRef global_props = CGImageSourceCopyProperties(src, options);
    if (global_props) {
        /* Force enumeration of all keys to trigger lazy parsing */
        CFIndex count = CFDictionaryGetCount(global_props);
        if (count > 0 && count < 10000) {
            const void **keys = malloc(sizeof(void*) * count);
            const void **vals = malloc(sizeof(void*) * count);
            if (keys && vals) {
                CFDictionaryGetKeysAndValues(global_props, keys, vals);
                /* Touch each value to force parsing */
                for (CFIndex i = 0; i < count; i++) {
                    if (vals[i] && CFGetTypeID(vals[i]) == CFStringGetTypeID()) {
                        CFIndex len = CFStringGetLength((CFStringRef)vals[i]);
                        (void)len;
                    }
                }
            }
            free(keys);
            free(vals);
        }
        CFRelease(global_props);
    }

    /* Per-image properties */
    size_t img_count = CGImageSourceGetCount(src);
    if (img_count > 4) img_count = 4;

    for (size_t i = 0; i < img_count; i++) {
        CFDictionaryRef props = CGImageSourceCopyPropertiesAtIndex(
            src, i, options);
        if (props) {
            /* Extract specific metadata dictionaries that have
             * their own complex parsers */
            const void *exif = CFDictionaryGetValue(props,
                kCGImagePropertyExifDictionary);
            const void *gps = CFDictionaryGetValue(props,
                kCGImagePropertyGPSDictionary);
            const void *tiff = CFDictionaryGetValue(props,
                kCGImagePropertyTIFFDictionary);
            const void *iptc = CFDictionaryGetValue(props,
                kCGImagePropertyIPTCDictionary);

            /* Touch to force parsing */
            (void)exif; (void)gps; (void)tiff; (void)iptc;

            CFRelease(props);
        }

        /* Also test getting the status per-image */
        CGImageSourceStatus status = CGImageSourceGetStatusAtIndex(src, i);
        (void)status;
    }

    CFRelease(src);
}

/* ================================================================
 * PATH 4: Incremental (streaming) parsing
 * This is how iMessage processes incoming images — it feeds bytes
 * incrementally as they arrive over the network. The incremental
 * parser maintains state between calls, and state corruption bugs
 * are a rich vulnerability class.
 *
 * We feed the data in variable-sized chunks to stress the parser's
 * state machine at different boundary points.
 * ================================================================ */
static void path_incremental(CFDataRef data, CFDictionaryRef options,
                             uint8_t chunk_strategy) {
    CGImageSourceRef src = CGImageSourceCreateIncremental(options);
    if (!src) {
        return;
    }

    const uint8_t *bytes = CFDataGetBytePtr(data);
    CFIndex total = CFDataGetLength(data);

    /* Determine chunk size strategy */
    size_t base_chunk;
    switch (chunk_strategy & 0x07) {
        case 0: base_chunk = 1;     break;  /* 1 byte at a time */
        case 1: base_chunk = 4;     break;  /* 4 bytes (word-aligned) */
        case 2: base_chunk = 16;    break;  /* 16 bytes */
        case 3: base_chunk = 64;    break;  /* 64 bytes */
        case 4: base_chunk = 256;   break;  /* 256 bytes */
        case 5: base_chunk = 1024;  break;  /* 1 KB */
        case 6: base_chunk = 4096;  break;  /* 4 KB (page-aligned) */
        case 7: base_chunk = total; break;  /* All at once */
    }

    CFIndex offset = 0;
    int iterations = 0;

    while (offset < total && iterations < 50000) {
        /* Vary chunk size slightly based on fuzz data to hit
         * different boundary conditions */
        size_t chunk = base_chunk;
        if (offset + 1 < total) {
            /* Use next byte to perturb chunk size ±50% */
            uint8_t perturb = bytes[(offset + 1) % total];
            chunk = base_chunk + (perturb % (base_chunk + 1)) - (base_chunk / 2);
            if (chunk == 0) chunk = 1;
            if (chunk > 8192) chunk = 8192;
        }

        CFIndex remaining = total - offset;
        if ((CFIndex)chunk > remaining) chunk = remaining;
        bool is_final = ((CFIndex)(offset + chunk) >= total);

        CFDataRef partial = CFDataCreate(
            kCFAllocatorDefault, bytes + offset, chunk);
        if (!partial) break;

        CGImageSourceUpdateData(src, partial, is_final);
        CFRelease(partial);

        /* Check status after each update */
        CGImageSourceStatus status = CGImageSourceGetStatus(src);

        /* Try to extract data at various stages */
        if (iterations % 10 == 0 || is_final) {
            /* Try thumbnail during streaming */
            CGImageRef thumb = CGImageSourceCreateThumbnailAtIndex(
                src, 0, options);
            if (thumb) CGImageRelease(thumb);

            /* Try metadata during streaming */
            CFDictionaryRef props = CGImageSourceCopyPropertiesAtIndex(
                src, 0, options);
            if (props) CFRelease(props);
        }

        /* If final, try full decode */
        if (is_final && status != kCGImageStatusInvalidData) {
            CGImageRef img = CGImageSourceCreateImageAtIndex(
                src, 0, options);
            if (img) {
                size_t w = CGImageGetWidth(img);
                size_t h = CGImageGetHeight(img);
                if (w > 0 && h > 0 && w <= 2048 && h <= 2048) {
                    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
                    CGContextRef ctx = CGBitmapContextCreate(
                        NULL, w, h, 8, w * 4, cs,
                        kCGImageAlphaPremultipliedLast);
                    if (ctx) {
                        CGContextDrawImage(ctx,
                            CGRectMake(0, 0, w, h), img);
                        CGContextRelease(ctx);
                    }
                    CGColorSpaceRelease(cs);
                }
                CGImageRelease(img);
            }
        }

        offset += chunk;
        iterations++;

        if (status == kCGImageStatusInvalidData) break;
    }

    CFRelease(src);
}

/* ================================================================
 * PATH 5: ICC Profile parsing
 * ICC profiles are embedded in most image formats and have their
 * own complex parsing logic. Bugs here affect ALL formats.
 * ================================================================ */
static void path_icc(CFDataRef data) {
    /* Try to parse as an ICC profile directly */
    CGColorSpaceRef cs = CGColorSpaceCreateWithICCData(data);
    if (cs) {
        /* Extract profile properties to force full parsing */
        CFDataRef profile = CGColorSpaceCopyICCData(cs);
        if (profile) {
            CFIndex len = CFDataGetLength(profile);
            (void)len;
            CFRelease(profile);
        }

        /* Get color space model */
        CGColorSpaceModel model = CGColorSpaceGetModel(cs);
        (void)model;

        size_t components = CGColorSpaceGetNumberOfComponents(cs);
        (void)components;

        CGColorSpaceRelease(cs);
    }
}

/* ================================================================
 * LLVMFuzzerTestOneInput — the libFuzzer entry point
 *
 * Input structure:
 *   byte 0:   Format selector (which image format to target)
 *   byte 1:   Path selector (which parsing path to exercise)
 *   byte 2:   Chunk strategy (for incremental path)
 *   byte 3:   Options flags (various CGImageSource options)
 *   bytes 4+: Fuzz data (appended AFTER format header)
 * ================================================================ */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) return 0;  /* Need at least control bytes + payload */

    uint8_t format_sel = data[0];
    uint8_t path_sel   = data[1];
    uint8_t chunk_sel  = data[2];
    uint8_t opt_flags  = data[3];

    /* Get format specification */
    FormatSpec fmt = get_format(format_sel);

    /* Build input: format header + fuzz data */
    size_t payload_size = size - 4;
    size_t total = (fmt.header ? fmt.header_len : 0) + payload_size;

    if (total > 256 * 1024) return 0;  /* Cap at 256KB to avoid OOM */

    uint8_t *input = malloc(total);
    if (!input) return 0;

    size_t offset = 0;
    if (fmt.header) {
        memcpy(input, fmt.header, fmt.header_len);
        offset = fmt.header_len;
    }
    memcpy(input + offset, data + 4, payload_size);

    /* Patch size fields in headers where applicable */
    if (format_sel >= 0x40 && format_sel < 0x60 && total >= 12) {
        /* WebP: patch RIFF size field */
        uint32_t riff_size = (uint32_t)(total - 8);
        input[4] = riff_size & 0xFF;
        input[5] = (riff_size >> 8) & 0xFF;
        input[6] = (riff_size >> 16) & 0xFF;
        input[7] = (riff_size >> 24) & 0xFF;
    }

    /* Create CFData from assembled input */
    CFDataRef cf_data = CFDataCreate(kCFAllocatorDefault, input, total);
    free(input);
    if (!cf_data) return 0;

    /* Build CGImageSource options */
    CFMutableDictionaryRef options = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);

    /* Set type hint if we have one */
    if (fmt.type_hint) {
        CFDictionarySetValue(options,
            kCGImageSourceTypeIdentifierHint, fmt.type_hint);
    }

    /* Option flags control various CGImageSource behaviors */
    if (opt_flags & 0x01) {
        CFDictionarySetValue(options,
            kCGImageSourceShouldCache, kCFBooleanFalse);
    }
    if (opt_flags & 0x02) {
        CFDictionarySetValue(options,
            kCGImageSourceShouldAllowFloat, kCFBooleanTrue);
    }

    /* Select parsing path based on fuzz input */
    switch (path_sel % 6) {
        case 0:
            /* Full decode — deepest parsing */
            path_full_decode(cf_data, options);
            break;

        case 1:
            /* Thumbnail generation — iMessage preview path */
            path_thumbnail(cf_data, options);
            break;

        case 2:
            /* Metadata extraction — EXIF/IPTC/XMP */
            path_metadata(cf_data, options);
            break;

        case 3:
            /* Incremental (streaming) — how iMessage receives images */
            path_incremental(cf_data, options, chunk_sel);
            break;

        case 4:
            /* ICC profile parsing */
            path_icc(cf_data);
            break;

        case 5:
            /* ALL PATHS — maximum coverage per input */
            path_metadata(cf_data, options);
            path_thumbnail(cf_data, options);
            path_full_decode(cf_data, options);
            path_icc(cf_data);
            break;
    }

    CFRelease(options);
    CFRelease(cf_data);
    return 0;
}
