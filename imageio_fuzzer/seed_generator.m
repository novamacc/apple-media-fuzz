/*
 * seed_generator.m — Generate minimal valid seed files for all 12 ImageIO formats
 *
 * Each seed is the SMALLEST valid file that ImageIO will accept for that format.
 * libFuzzer mutates these seeds to explore parser branches.
 *
 * Build:
 *   clang -framework ImageIO -framework CoreGraphics -framework CoreFoundation \
 *         -o seed_generator seed_generator.m
 *
 * Run:
 *   ./seed_generator corpus/
 */

#import <ImageIO/ImageIO.h>
#import <CoreGraphics/CoreGraphics.h>
#import <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static void write_seed(const char *dir, const char *name,
                        const uint8_t *data, size_t len) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "wb");
    if (f) {
        fwrite(data, 1, len, f);
        fclose(f);
        printf("  [+] %s (%zu bytes)\n", name, len);
    } else {
        printf("  [-] Failed to write %s\n", name);
    }
}

/* Generate a minimal valid PNG using CoreGraphics */
static void generate_png_seed(const char *dir) {
    int w = 8, h = 8;
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGContextRef ctx = CGBitmapContextCreate(
        NULL, w, h, 8, w * 4, cs,
        kCGImageAlphaPremultipliedLast);

    /* Draw something to make it non-trivial */
    CGContextSetRGBFillColor(ctx, 1.0, 0.0, 0.0, 1.0);
    CGContextFillRect(ctx, CGRectMake(0, 0, 4, 4));
    CGContextSetRGBFillColor(ctx, 0.0, 0.0, 1.0, 1.0);
    CGContextFillRect(ctx, CGRectMake(4, 4, 4, 4));

    CGImageRef img = CGBitmapContextCreateImage(ctx);

    /* Write as PNG */
    CFMutableDataRef png_data = CFDataCreateMutable(kCFAllocatorDefault, 0);
    CGImageDestinationRef dest = CGImageDestinationCreateWithData(
        png_data, CFSTR("public.png"), 1, NULL);
    CGImageDestinationAddImage(dest, img, NULL);
    CGImageDestinationFinalize(dest);

    write_seed(dir, "seed_png.png",
               CFDataGetBytePtr(png_data), CFDataGetLength(png_data));

    CFRelease(dest);
    CFRelease(png_data);
    CGImageRelease(img);
    CGContextRelease(ctx);
    CGColorSpaceRelease(cs);
}

/* Generate a minimal valid TIFF */
static void generate_tiff_seed(const char *dir) {
    int w = 8, h = 8;
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGContextRef ctx = CGBitmapContextCreate(
        NULL, w, h, 8, w * 4, cs,
        kCGImageAlphaPremultipliedLast);
    CGContextSetRGBFillColor(ctx, 0.0, 1.0, 0.0, 1.0);
    CGContextFillRect(ctx, CGRectMake(0, 0, w, h));
    CGImageRef img = CGBitmapContextCreateImage(ctx);

    CFMutableDataRef tiff_data = CFDataCreateMutable(kCFAllocatorDefault, 0);
    CGImageDestinationRef dest = CGImageDestinationCreateWithData(
        tiff_data, CFSTR("public.tiff"), 1, NULL);
    CGImageDestinationAddImage(dest, img, NULL);
    CGImageDestinationFinalize(dest);

    write_seed(dir, "seed_tiff.tiff",
               CFDataGetBytePtr(tiff_data), CFDataGetLength(tiff_data));

    CFRelease(dest);
    CFRelease(tiff_data);
    CGImageRelease(img);
    CGContextRelease(ctx);
    CGColorSpaceRelease(cs);
}

/* Generate a minimal valid GIF */
static void generate_gif_seed(const char *dir) {
    int w = 8, h = 8;
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGContextRef ctx = CGBitmapContextCreate(
        NULL, w, h, 8, w * 4, cs,
        kCGImageAlphaPremultipliedLast);
    CGContextSetRGBFillColor(ctx, 1.0, 1.0, 0.0, 1.0);
    CGContextFillRect(ctx, CGRectMake(0, 0, w, h));
    CGImageRef img = CGBitmapContextCreateImage(ctx);

    CFMutableDataRef gif_data = CFDataCreateMutable(kCFAllocatorDefault, 0);
    CGImageDestinationRef dest = CGImageDestinationCreateWithData(
        gif_data, CFSTR("com.compuserve.gif"), 1, NULL);
    CGImageDestinationAddImage(dest, img, NULL);
    CGImageDestinationFinalize(dest);

    write_seed(dir, "seed_gif.gif",
               CFDataGetBytePtr(gif_data), CFDataGetLength(gif_data));

    CFRelease(dest);
    CFRelease(gif_data);
    CGImageRelease(img);
    CGContextRelease(ctx);
    CGColorSpaceRelease(cs);
}

/* Generate a minimal valid BMP */
static void generate_bmp_seed(const char *dir) {
    int w = 8, h = 8;
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGContextRef ctx = CGBitmapContextCreate(
        NULL, w, h, 8, w * 4, cs,
        kCGImageAlphaPremultipliedLast);
    CGContextSetRGBFillColor(ctx, 0.5, 0.0, 0.5, 1.0);
    CGContextFillRect(ctx, CGRectMake(0, 0, w, h));
    CGImageRef img = CGBitmapContextCreateImage(ctx);

    CFMutableDataRef bmp_data = CFDataCreateMutable(kCFAllocatorDefault, 0);
    CGImageDestinationRef dest = CGImageDestinationCreateWithData(
        bmp_data, CFSTR("com.microsoft.bmp"), 1, NULL);
    CGImageDestinationAddImage(dest, img, NULL);
    CGImageDestinationFinalize(dest);

    write_seed(dir, "seed_bmp.bmp",
               CFDataGetBytePtr(bmp_data), CFDataGetLength(bmp_data));

    CFRelease(dest);
    CFRelease(bmp_data);
    CGImageRelease(img);
    CGContextRelease(ctx);
    CGColorSpaceRelease(cs);
}

/* Generate a minimal valid JPEG2000 */
static void generate_jp2_seed(const char *dir) {
    int w = 8, h = 8;
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGContextRef ctx = CGBitmapContextCreate(
        NULL, w, h, 8, w * 4, cs,
        kCGImageAlphaPremultipliedLast);
    CGContextSetRGBFillColor(ctx, 0.0, 0.5, 0.5, 1.0);
    CGContextFillRect(ctx, CGRectMake(0, 0, w, h));
    CGImageRef img = CGBitmapContextCreateImage(ctx);

    CFMutableDataRef jp2_data = CFDataCreateMutable(kCFAllocatorDefault, 0);
    CGImageDestinationRef dest = CGImageDestinationCreateWithData(
        jp2_data, CFSTR("public.jpeg-2000"), 1, NULL);
    if (dest) {
        CGImageDestinationAddImage(dest, img, NULL);
        CGImageDestinationFinalize(dest);
        write_seed(dir, "seed_jp2.jp2",
                   CFDataGetBytePtr(jp2_data), CFDataGetLength(jp2_data));
        CFRelease(dest);
    }

    CFRelease(jp2_data);
    CGImageRelease(img);
    CGContextRelease(ctx);
    CGColorSpaceRelease(cs);
}

/* Generate a minimal HEIF seed */
static void generate_heif_seed(const char *dir) {
    int w = 8, h = 8;
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGContextRef ctx = CGBitmapContextCreate(
        NULL, w, h, 8, w * 4, cs,
        kCGImageAlphaPremultipliedLast);
    CGContextSetRGBFillColor(ctx, 1.0, 0.5, 0.0, 1.0);
    CGContextFillRect(ctx, CGRectMake(0, 0, w, h));
    CGImageRef img = CGBitmapContextCreateImage(ctx);

    CFMutableDataRef heif_data = CFDataCreateMutable(kCFAllocatorDefault, 0);
    CGImageDestinationRef dest = CGImageDestinationCreateWithData(
        heif_data, CFSTR("public.heic"), 1, NULL);
    if (dest) {
        CGImageDestinationAddImage(dest, img, NULL);
        CGImageDestinationFinalize(dest);
        write_seed(dir, "seed_heic.heic",
                   CFDataGetBytePtr(heif_data), CFDataGetLength(heif_data));
        CFRelease(dest);
    }

    CFRelease(heif_data);
    CGImageRelease(img);
    CGContextRelease(ctx);
    CGColorSpaceRelease(cs);
}

/* Generate a minimal valid ICO (raw bytes) */
static void generate_ico_seed(const char *dir) {
    /* 16x16, 32-bit ICO with BMP image data */
    uint8_t ico[1078];
    memset(ico, 0, sizeof(ico));

    /* ICONDIR */
    ico[2] = 0x01; ico[3] = 0x00; /* Type: 1 (icon) */
    ico[4] = 0x01; ico[5] = 0x00; /* Count: 1 */

    /* ICONDIRENTRY */
    ico[6]  = 16;   /* Width */
    ico[7]  = 16;   /* Height */
    ico[10] = 1;    /* Color planes */
    ico[12] = 32;   /* Bits per pixel */
    /* Image data size = 40 (BIH) + 16*16*4 (pixels) = 1064 */
    ico[14] = 0x28; ico[15] = 0x04;
    /* Offset to image data = 22 */
    ico[18] = 22;

    /* BITMAPINFOHEADER at offset 22 */
    ico[22] = 40;   /* biSize */
    ico[26] = 16;   /* biWidth */
    ico[30] = 32;   /* biHeight (2x for AND mask) */
    ico[34] = 1;    /* biPlanes */
    ico[36] = 32;   /* biBitCount */

    /* Pixel data: gradient pattern */
    for (int y = 0; y < 16; y++) {
        for (int x = 0; x < 16; x++) {
            int off = 62 + (y * 16 + x) * 4;
            if (off + 3 < (int)sizeof(ico)) {
                ico[off] = x * 16;       /* B */
                ico[off+1] = y * 16;     /* G */
                ico[off+2] = 128;        /* R */
                ico[off+3] = 255;        /* A */
            }
        }
    }

    write_seed(dir, "seed_ico.ico", ico, sizeof(ico));
}

/* Generate minimal PSD seed */
static void generate_psd_seed(const char *dir) {
    /* Minimal PSD: header + empty color mode + empty resources +
     * empty layers + image data */
    uint8_t psd[512];
    memset(psd, 0, sizeof(psd));
    size_t pos = 0;

    /* Signature "8BPS" */
    psd[pos++] = 0x38; psd[pos++] = 0x42;
    psd[pos++] = 0x50; psd[pos++] = 0x53;
    /* Version: 1 */
    psd[pos++] = 0x00; psd[pos++] = 0x01;
    /* Reserved (6 bytes) */
    pos += 6;
    /* Channels: 3 */
    psd[pos++] = 0x00; psd[pos++] = 0x03;
    /* Height: 4 */
    psd[pos++] = 0x00; psd[pos++] = 0x00;
    psd[pos++] = 0x00; psd[pos++] = 0x04;
    /* Width: 4 */
    psd[pos++] = 0x00; psd[pos++] = 0x00;
    psd[pos++] = 0x00; psd[pos++] = 0x04;
    /* Depth: 8 */
    psd[pos++] = 0x00; psd[pos++] = 0x08;
    /* Color mode: 3 (RGB) */
    psd[pos++] = 0x00; psd[pos++] = 0x03;

    /* Color mode data length: 0 */
    psd[pos++] = 0x00; psd[pos++] = 0x00;
    psd[pos++] = 0x00; psd[pos++] = 0x00;

    /* Image resources length: 0 */
    psd[pos++] = 0x00; psd[pos++] = 0x00;
    psd[pos++] = 0x00; psd[pos++] = 0x00;

    /* Layer and mask info length: 0 */
    psd[pos++] = 0x00; psd[pos++] = 0x00;
    psd[pos++] = 0x00; psd[pos++] = 0x00;

    /* Image data: compression=0 (raw) */
    psd[pos++] = 0x00; psd[pos++] = 0x00;

    /* Raw pixel data: 3 channels × 4×4 = 48 bytes */
    for (int i = 0; i < 48; i++) {
        psd[pos++] = (i * 5) & 0xFF;
    }

    write_seed(dir, "seed_psd.psd", psd, pos);
}

/* Generate minimal DNG seed (TIFF-based with DNG tags) */
static void generate_dng_seed(const char *dir) {
    /* Use CG to make a TIFF, then manually patch in DNG tags */
    int w = 8, h = 8;
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGContextRef ctx = CGBitmapContextCreate(
        NULL, w, h, 8, w * 4, cs,
        kCGImageAlphaPremultipliedLast);
    CGContextSetRGBFillColor(ctx, 0.2, 0.4, 0.6, 1.0);
    CGContextFillRect(ctx, CGRectMake(0, 0, w, h));
    CGImageRef img = CGBitmapContextCreateImage(ctx);

    /* Write as TIFF first (DNG is TIFF-based) */
    CFMutableDataRef tiff_data = CFDataCreateMutable(kCFAllocatorDefault, 0);
    CGImageDestinationRef dest = CGImageDestinationCreateWithData(
        tiff_data, CFSTR("public.tiff"), 1, NULL);

    /* Add DNG-specific properties */
    CFMutableDictionaryRef props = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);

    CGImageDestinationAddImage(dest, img, props);
    CGImageDestinationFinalize(dest);

    /* Save as .dng (ImageIO will recognize the TIFF structure) */
    write_seed(dir, "seed_dng.dng",
               CFDataGetBytePtr(tiff_data), CFDataGetLength(tiff_data));

    CFRelease(props);
    CFRelease(dest);
    CFRelease(tiff_data);
    CGImageRelease(img);
    CGContextRelease(ctx);
    CGColorSpaceRelease(cs);
}

/* Generate ICC profile seed */
static void generate_icc_seed(const char *dir) {
    /* Use sRGB profile as seed */
    CGColorSpaceRef srgb = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
    if (srgb) {
        CFDataRef icc_data = CGColorSpaceCopyICCData(srgb);
        if (icc_data) {
            write_seed(dir, "seed_icc.icc",
                       CFDataGetBytePtr(icc_data),
                       CFDataGetLength(icc_data));
            CFRelease(icc_data);
        }
        CGColorSpaceRelease(srgb);
    }

    /* Also generate Display P3 profile */
    CGColorSpaceRef p3 = CGColorSpaceCreateWithName(
        kCGColorSpaceDisplayP3);
    if (p3) {
        CFDataRef p3_data = CGColorSpaceCopyICCData(p3);
        if (p3_data) {
            write_seed(dir, "seed_icc_p3.icc",
                       CFDataGetBytePtr(p3_data),
                       CFDataGetLength(p3_data));
            CFRelease(p3_data);
        }
        CGColorSpaceRelease(p3);
    }
}

/* Generate JPEG seed with EXIF metadata */
static void generate_jpeg_seed(const char *dir) {
    int w = 8, h = 8;
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGContextRef ctx = CGBitmapContextCreate(
        NULL, w, h, 8, w * 4, cs,
        kCGImageAlphaPremultipliedLast);
    CGContextSetRGBFillColor(ctx, 0.8, 0.2, 0.1, 1.0);
    CGContextFillRect(ctx, CGRectMake(0, 0, w, h));
    CGImageRef img = CGBitmapContextCreateImage(ctx);

    CFMutableDataRef jpeg_data = CFDataCreateMutable(kCFAllocatorDefault, 0);
    CGImageDestinationRef dest = CGImageDestinationCreateWithData(
        jpeg_data, CFSTR("public.jpeg"), 1, NULL);

    /* Add EXIF metadata as additional attack surface */
    CFMutableDictionaryRef props = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    CFMutableDictionaryRef exif = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(exif, kCGImagePropertyExifUserComment,
                         CFSTR("FuzzSeed"));
    CFDictionarySetValue(props, kCGImagePropertyExifDictionary, exif);

    CGImageDestinationAddImage(dest, img, props);
    CGImageDestinationFinalize(dest);

    write_seed(dir, "seed_jpeg.jpg",
               CFDataGetBytePtr(jpeg_data), CFDataGetLength(jpeg_data));

    CFRelease(exif);
    CFRelease(props);
    CFRelease(dest);
    CFRelease(jpeg_data);
    CGImageRelease(img);
    CGContextRelease(ctx);
    CGColorSpaceRelease(cs);
}

int main(int argc, char *argv[]) {
    const char *output_dir = argc > 1 ? argv[1] : "corpus";

    mkdir(output_dir, 0755);

    printf("[*] Generating ImageIO seed corpus in %s/\n", output_dir);

    generate_png_seed(output_dir);
    generate_tiff_seed(output_dir);
    generate_gif_seed(output_dir);
    generate_bmp_seed(output_dir);
    generate_jp2_seed(output_dir);
    generate_heif_seed(output_dir);
    generate_ico_seed(output_dir);
    generate_psd_seed(output_dir);
    generate_dng_seed(output_dir);
    generate_icc_seed(output_dir);
    generate_jpeg_seed(output_dir);

    printf("\n[+] Seed corpus generation complete.\n");
    printf("    Run fuzzer: ./fuzz_imageio %s/ -max_len=65536 -timeout=10\n",
           output_dir);
    return 0;
}
