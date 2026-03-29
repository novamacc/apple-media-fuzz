/*
 * fuzz_transcoder.m — IMTranscoderAgent Image Transcoding Fuzzer
 *
 * ═══════════════════════════════════════════════════════════════════════
 * TARGET: IMTranscoderAgent (iMessage image/video transcoder)
 *
 * FORCEDENTRY used this exact process for sandbox escape.
 * IMTranscoderAgent receives images via XPC, transcodes them
 * (HEIC→JPEG, GIF→PNG, resize, thumbnail), exercises ImageIO,
 * CoreGraphics, and format-specific codecs.
 *
 * FUZZING PATHS (6):
 *   [0] Multi-format decode + re-encode to JPEG
 *   [1] HEIC/HEIF container parsing + thumbnail generation
 *   [2] GIF animation frame extraction
 *   [3] Image resize/resample pipeline
 *   [4] ICC profile + color space conversion
 *   [5] WebP decode → re-encode pipeline
 *
 * Build:
 *   clang -framework Foundation -framework ImageIO \
 *         -framework CoreGraphics -framework CoreFoundation \
 *         -framework CoreImage \
 *         -fsanitize=fuzzer,address,undefined -g -O1 \
 *         -o fuzz_transcoder fuzz_transcoder.m
 * ═══════════════════════════════════════════════════════════════════════
 */

#import <Foundation/Foundation.h>
#import <ImageIO/ImageIO.h>
#import <CoreGraphics/CoreGraphics.h>
#include <stdint.h>
#include <string.h>

/* Max image dimensions to prevent OOM */
#define MAX_DIM 2048
#define MAX_PIXELS (MAX_DIM * MAX_DIM)

static CGImageRef decode_image(const uint8_t *data, size_t size) {
    NSData *nsdata = [NSData dataWithBytesNoCopy:(void *)data
                                          length:size freeWhenDone:NO];
    CGImageSourceRef src = CGImageSourceCreateWithData(
        (__bridge CFDataRef)nsdata, NULL);
    if (!src) return NULL;

    NSDictionary *opts = @{
        (__bridge NSString *)kCGImageSourceShouldCache: @NO,
    };
    CGImageRef img = CGImageSourceCreateImageAtIndex(
        src, 0, (__bridge CFDictionaryRef)opts);
    CFRelease(src);

    /* Validate dimensions */
    if (img) {
        size_t w = CGImageGetWidth(img);
        size_t h = CGImageGetHeight(img);
        if (w > MAX_DIM || h > MAX_DIM || (w * h) > MAX_PIXELS) {
            CGImageRelease(img);
            return NULL;
        }
    }
    return img;
}

/* ================================================================
 * PATH 0: Multi-format decode → JPEG re-encode
 * Simulates IMTranscoderAgent's primary transcoding pipeline
 * ================================================================ */
static void fuzz_transcode_jpeg(const uint8_t *data, size_t size) {
    @autoreleasepool {
        CGImageRef img = decode_image(data, size);
        if (!img) return;

        size_t w = CGImageGetWidth(img);
        size_t h = CGImageGetHeight(img);

        /* Render to bitmap (forces full decode) */
        CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
        CGContextRef ctx = CGBitmapContextCreate(
            NULL, w, h, 8, w * 4, cs,
            (CGBitmapInfo)kCGImageAlphaPremultipliedLast);
        CGColorSpaceRelease(cs);

        if (ctx) {
            CGContextDrawImage(ctx, CGRectMake(0, 0, w, h), img);
            CGImageRef rendered = CGBitmapContextCreateImage(ctx);

            if (rendered) {
                /* Re-encode as JPEG (transcoding pipeline) */
                NSMutableData *output = [NSMutableData data];
                CGImageDestinationRef dest = CGImageDestinationCreateWithData(
                    (__bridge CFMutableDataRef)output,
                    CFSTR("public.jpeg"), 1, NULL);
                if (dest) {
                    NSDictionary *props = @{
                        (__bridge NSString *)kCGImageDestinationLossyCompressionQuality: @(0.8),
                    };
                    CGImageDestinationAddImage(dest, rendered,
                        (__bridge CFDictionaryRef)props);
                    CGImageDestinationFinalize(dest);
                    CFRelease(dest);
                }
                CGImageRelease(rendered);
            }
            CGContextRelease(ctx);
        }
        CGImageRelease(img);
    }
}

/* ================================================================
 * PATH 1: HEIC/HEIF thumbnail generation
 * ================================================================ */
static void fuzz_heif_thumbnail(const uint8_t *data, size_t size) {
    @autoreleasepool {
        NSData *nsdata = [NSData dataWithBytesNoCopy:(void *)data
                                              length:size freeWhenDone:NO];
        CGImageSourceRef src = CGImageSourceCreateWithData(
            (__bridge CFDataRef)nsdata, NULL);
        if (!src) return;

        /* Get image properties (parses container metadata) */
        CFDictionaryRef props = CGImageSourceCopyProperties(src, NULL);
        if (props) CFRelease(props);

        size_t count = CGImageSourceGetCount(src);
        if (count > 20) count = 20;

        for (size_t i = 0; i < count; i++) {
            CFDictionaryRef frameProps = CGImageSourceCopyPropertiesAtIndex(
                src, i, NULL);
            if (frameProps) CFRelease(frameProps);

            /* Generate thumbnail (different code path than full decode) */
            NSDictionary *thumbOpts = @{
                (__bridge NSString *)kCGImageSourceCreateThumbnailFromImageAlways: @YES,
                (__bridge NSString *)kCGImageSourceThumbnailMaxPixelSize: @(256),
                (__bridge NSString *)kCGImageSourceCreateThumbnailWithTransform: @YES,
            };
            CGImageRef thumb = CGImageSourceCreateThumbnailAtIndex(
                src, i, (__bridge CFDictionaryRef)thumbOpts);
            if (thumb) {
                (void)CGImageGetWidth(thumb);
                (void)CGImageGetHeight(thumb);
                CGImageRelease(thumb);
            }
        }

        CFStringRef type = CGImageSourceGetType(src);
        (void)type;
        CFRelease(src);
    }
}

/* ================================================================
 * PATH 2: GIF animation frame extraction
 * ================================================================ */
static void fuzz_gif_frames(const uint8_t *data, size_t size) {
    @autoreleasepool {
        NSData *nsdata = [NSData dataWithBytesNoCopy:(void *)data
                                              length:size freeWhenDone:NO];
        CGImageSourceRef src = CGImageSourceCreateWithData(
            (__bridge CFDataRef)nsdata, NULL);
        if (!src) return;

        size_t count = CGImageSourceGetCount(src);
        if (count > 50) count = 50; /* Limit frames */

        for (size_t i = 0; i < count; i++) {
            /* Decode each frame */
            CGImageRef frame = CGImageSourceCreateImageAtIndex(src, i, NULL);
            if (frame) {
                size_t w = CGImageGetWidth(frame);
                size_t h = CGImageGetHeight(frame);
                if (w <= MAX_DIM && h <= MAX_DIM) {
                    (void)CGImageGetBitsPerComponent(frame);
                    (void)CGImageGetBitsPerPixel(frame);
                    (void)CGImageGetBytesPerRow(frame);
                    CGColorSpaceRef cs = CGImageGetColorSpace(frame);
                    (void)cs;
                }
                CGImageRelease(frame);
            }

            /* Frame properties (delay time, disposal method) */
            CFDictionaryRef frameProps = CGImageSourceCopyPropertiesAtIndex(
                src, i, NULL);
            if (frameProps) {
                CFDictionaryRef gifProps;
                if (CFDictionaryGetValueIfPresent(frameProps,
                    kCGImagePropertyGIFDictionary,
                    (const void **)&gifProps)) {
                    (void)CFDictionaryGetCount(gifProps);
                }
                CFRelease(frameProps);
            }
        }
        CFRelease(src);
    }
}

/* ================================================================
 * PATH 3: Image resize/resample
 * ================================================================ */
static void fuzz_resize(const uint8_t *data, size_t size) {
    @autoreleasepool {
        if (size < 4) return;

        /* Use first 2 bytes for target dimensions */
        uint16_t tw = (data[0] % 128) + 1;
        uint16_t th = (data[1] % 128) + 1;

        CGImageRef img = decode_image(data + 2, size - 2);
        if (!img) return;

        /* Resize using CGBitmapContext (simulates iMessage thumbnail) */
        CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
        CGContextRef ctx = CGBitmapContextCreate(
            NULL, tw, th, 8, tw * 4, cs,
            (CGBitmapInfo)kCGImageAlphaPremultipliedLast);
        CGColorSpaceRelease(cs);

        if (ctx) {
            CGContextSetInterpolationQuality(ctx, kCGInterpolationHigh);
            CGContextDrawImage(ctx, CGRectMake(0, 0, tw, th), img);

            CGImageRef resized = CGBitmapContextCreateImage(ctx);
            if (resized) {
                /* Re-encode resized image as PNG */
                NSMutableData *output = [NSMutableData data];
                CGImageDestinationRef dest = CGImageDestinationCreateWithData(
                    (__bridge CFMutableDataRef)output,
                    CFSTR("public.png"), 1, NULL);
                if (dest) {
                    CGImageDestinationAddImage(dest, resized, NULL);
                    CGImageDestinationFinalize(dest);
                    CFRelease(dest);
                }
                CGImageRelease(resized);
            }
            CGContextRelease(ctx);
        }
        CGImageRelease(img);
    }
}

/* ================================================================
 * PATH 4: ICC profile + color space conversion
 * ================================================================ */
static void fuzz_color_convert(const uint8_t *data, size_t size) {
    @autoreleasepool {
        CGImageRef img = decode_image(data, size);
        if (!img) return;

        size_t w = CGImageGetWidth(img);
        size_t h = CGImageGetHeight(img);

        /* Source color space from image */
        CGColorSpaceRef srcCS = CGImageGetColorSpace(img);
        if (srcCS) {
            (void)CGColorSpaceGetModel(srcCS);
            (void)CGColorSpaceGetNumberOfComponents(srcCS);
            CFDataRef iccData = CGColorSpaceCopyICCData(srcCS);
            if (iccData) {
                (void)CFDataGetLength(iccData);
                CFRelease(iccData);
            }
        }

        /* Convert to sRGB */
        CGColorSpaceRef srgb = CGColorSpaceCreateWithName(
            kCGColorSpaceSRGB);
        if (srgb && w > 0 && h > 0 && w <= 512 && h <= 512) {
            CGContextRef ctx = CGBitmapContextCreate(
                NULL, w, h, 8, w * 4, srgb,
                (CGBitmapInfo)kCGImageAlphaPremultipliedLast);
            if (ctx) {
                CGContextDrawImage(ctx, CGRectMake(0, 0, w, h), img);
                CGImageRef converted = CGBitmapContextCreateImage(ctx);
                if (converted) CGImageRelease(converted);
                CGContextRelease(ctx);
            }
        }
        if (srgb) CGColorSpaceRelease(srgb);
        CGImageRelease(img);
    }
}

/* ================================================================
 * PATH 5: Incremental image loading (progressive JPEG/PNG)
 * ================================================================ */
static void fuzz_incremental(const uint8_t *data, size_t size) {
    @autoreleasepool {
        CGImageSourceRef src = CGImageSourceCreateIncremental(NULL);
        if (!src) return;

        /* Feed data incrementally in chunks */
        size_t chunkSize = 64;
        for (size_t off = 0; off < size; off += chunkSize) {
            size_t thisChunk = MIN(chunkSize, size - off);
            BOOL final = (off + thisChunk >= size);

            NSData *chunk = [NSData dataWithBytesNoCopy:(void *)(data + off)
                                                 length:thisChunk
                                           freeWhenDone:NO];
            /* Accumulate */
            NSMutableData *accumulated = [NSMutableData dataWithBytes:data
                                                               length:off + thisChunk];
            CGImageSourceUpdateData(src,
                (__bridge CFDataRef)accumulated, final);

            CGImageSourceStatus status = CGImageSourceGetStatus(src);
            if (status == kCGImageStatusComplete ||
                status == kCGImageStatusInvalidData) {
                break;
            }

            /* Try partial decode */
            if (CGImageSourceGetCount(src) > 0) {
                CGImageRef partial = CGImageSourceCreateImageAtIndex(
                    src, 0, NULL);
                if (partial) {
                    (void)CGImageGetWidth(partial);
                    CGImageRelease(partial);
                }
            }
        }
        CFRelease(src);
    }
}

/* ================================================================ */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) return 0;

    @autoreleasepool {
        uint8_t path = data[0];
        const uint8_t *payload = data + 1;
        size_t psize = size - 1;

        switch (path % 6) {
            case 0: fuzz_transcode_jpeg(payload, psize);  break;
            case 1: fuzz_heif_thumbnail(payload, psize);  break;
            case 2: fuzz_gif_frames(payload, psize);      break;
            case 3: fuzz_resize(payload, psize);           break;
            case 4: fuzz_color_convert(payload, psize);    break;
            case 5: fuzz_incremental(payload, psize);      break;
        }
    }
    return 0;
}
