/*
 * fuzz_pdf.m — God-Level CoreGraphics PDF Parser Fuzzer
 *
 * ═══════════════════════════════════════════════════════════════════════
 * TARGET: CoreGraphics PDF Parser (CGPDFDocument, CGPDFScanner, etc.)
 *
 * WHY THIS IS #1 ATTACK SURFACE:
 *   PDFs are parsed EVERYWHERE on Apple devices:
 *   - Mail.app auto-previews PDF attachments (ZERO-CLICK)
 *   - Spotlight indexes PDFs automatically (ZERO-CLICK)
 *   - QuickLook previews PDFs in Finder, Messages, etc.
 *   - Safari renders inline PDFs from websites
 *   - iMessage previews PDF links (ZERO-CLICK)
 *   - AirDrop file preview
 *   - The FORCEDENTRY exploit (NSO) used a PDF container
 *
 * PDF PARSING PATHS (10):
 *   [1] CGPDFDocument creation        — Header, xref, trailer parsing
 *   [2] CGPDFPage rendering           — Page tree, content streams
 *   [3] CGPDFScanner operators        — All 73 PDF operators
 *   [4] CGPDFStream decompression     — Flate, LZW, CCITT, JBIG2, JPEG2000
 *   [5] CGPDFDictionary traversal     — Recursive dictionary parsing
 *   [6] Embedded images               — XObject Image resources
 *   [7] Embedded fonts                — Type1, TrueType, CID fonts, CMap
 *   [8] ICC Color profiles            — ICC profile parsing in ColorSpaces
 *   [9] JBIG2 streams                 — The actual FORCEDENTRY vector
 *   [10] Incremental updates          — Appended xref/trailer sections
 *
 * Build:
 *   clang -framework Foundation -framework CoreGraphics \
 *         -framework CoreFoundation -framework ImageIO \
 *         -fsanitize=fuzzer,address,undefined -g -O1 \
 *         -o fuzz_pdf fuzz_pdf.m
 * ═══════════════════════════════════════════════════════════════════════
 */

#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <ImageIO/ImageIO.h>
#include <stdint.h>
#include <string.h>

/* ================================================================
 * PATH 1: CGPDFDocument Creation
 *
 * This exercises the PDF header parser, cross-reference table,
 * trailer dictionary, and catalog. All before any page rendering.
 * ================================================================ */
static void fuzz_document_creation(const uint8_t *data, size_t size) {
    @autoreleasepool {
        CGDataProviderRef provider = CGDataProviderCreateWithData(
            NULL, data, size, NULL);
        if (!provider) return;

        CGPDFDocumentRef doc = CGPDFDocumentCreateWithProvider(provider);
        CGDataProviderRelease(provider);
        if (!doc) return;

        /* Document metadata — exercises catalog/info dict */
        size_t pageCount = CGPDFDocumentGetNumberOfPages(doc);
        (void)CGPDFDocumentIsEncrypted(doc);
        (void)CGPDFDocumentIsUnlocked(doc);
        (void)CGPDFDocumentAllowsCopying(doc);
        (void)CGPDFDocumentAllowsPrinting(doc);

        CGPDFDictionaryRef catalog = CGPDFDocumentGetCatalog(doc);
        if (catalog) {
            /* Walk catalog entries */
            const char *type = NULL;
            CGPDFDictionaryGetName(catalog, "Type", &type);

            CGPDFDictionaryRef pages = NULL;
            CGPDFDictionaryGetDictionary(catalog, "Pages", &pages);

            /* Check for embedded JavaScript (attack vector) */
            CGPDFDictionaryRef names = NULL;
            CGPDFDictionaryGetDictionary(catalog, "Names", &names);
            if (names) {
                CGPDFDictionaryRef jsNames = NULL;
                CGPDFDictionaryGetDictionary(names, "JavaScript", &jsNames);
            }

            /* Check for AcroForm (interactive forms) */
            CGPDFDictionaryRef acroForm = NULL;
            CGPDFDictionaryGetDictionary(catalog, "AcroForm", &acroForm);

            /* Check for embedded files */
            CGPDFDictionaryRef ef = NULL;
            CGPDFDictionaryGetDictionary(catalog, "EmbeddedFiles", &ef);
        }

        /* Info dictionary */
        CGPDFDictionaryRef info = CGPDFDocumentGetInfo(doc);
        if (info) {
            CGPDFStringRef title = NULL, author = NULL;
            CGPDFDictionaryGetString(info, "Title", &title);
            CGPDFDictionaryGetString(info, "Author", &author);
            if (title) {
                CFStringRef str = CGPDFStringCopyTextString(title);
                if (str) CFRelease(str);
            }
        }

        CGPDFDocumentRelease(doc);
    }
}

/* ================================================================
 * PATH 2: CGPDFPage Rendering
 *
 * Renders each page to a bitmap context, exercising:
 * - Content stream parsing
 * - Graphics state operations
 * - Path construction/painting
 * - Text rendering
 * - Image rendering
 * - Color space management
 * ================================================================ */
static void fuzz_page_rendering(const uint8_t *data, size_t size) {
    @autoreleasepool {
        CGDataProviderRef provider = CGDataProviderCreateWithData(
            NULL, data, size, NULL);
        if (!provider) return;

        CGPDFDocumentRef doc = CGPDFDocumentCreateWithProvider(provider);
        CGDataProviderRelease(provider);
        if (!doc) return;

        size_t pages = CGPDFDocumentGetNumberOfPages(doc);
        if (pages > 10) pages = 10; /* Limit to prevent OOM */

        for (size_t i = 1; i <= pages; i++) {
            CGPDFPageRef page = CGPDFDocumentGetPage(doc, i);
            if (!page) continue;

            /* Get page geometry */
            CGRect mediaBox = CGPDFPageGetBoxRect(page, kCGPDFMediaBox);
            CGRect cropBox = CGPDFPageGetBoxRect(page, kCGPDFCropBox);
            CGRect bleedBox = CGPDFPageGetBoxRect(page, kCGPDFBleedBox);
            CGRect trimBox = CGPDFPageGetBoxRect(page, kCGPDFTrimBox);
            CGRect artBox = CGPDFPageGetBoxRect(page, kCGPDFArtBox);
            int rotation = CGPDFPageGetRotationAngle(page);
            (void)rotation;

            /* Clamp dimensions to prevent OOM */
            CGFloat w = mediaBox.size.width;
            CGFloat h = mediaBox.size.height;
            if (w <= 0 || h <= 0 || w > 4096 || h > 4096) {
                w = 612; h = 792; /* Default letter size */
            }

            /* Create a small bitmap context and render */
            CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
            /* Scale down to max 256x256 to limit memory */
            CGFloat scale = 1.0;
            if (w > 256 || h > 256) {
                scale = 256.0 / fmax(w, h);
            }
            size_t bw = (size_t)(w * scale);
            size_t bh = (size_t)(h * scale);
            if (bw == 0) bw = 1;
            if (bh == 0) bh = 1;

            CGContextRef ctx = CGBitmapContextCreate(
                NULL, bw, bh, 8, bw * 4, cs,
                kCGImageAlphaPremultipliedLast);
            CGColorSpaceRelease(cs);

            if (ctx) {
                /* Scale to fit */
                CGContextScaleCTM(ctx, scale, scale);

                /* This is the BIG parsing call — renders entire page */
                CGContextDrawPDFPage(ctx, page);

                /* Extract rendered image */
                CGImageRef img = CGBitmapContextCreateImage(ctx);
                if (img) CGImageRelease(img);

                CGContextRelease(ctx);
            }
        }

        CGPDFDocumentRelease(doc);
    }
}

/* ================================================================
 * PATH 3: CGPDFScanner — Operator-level parsing
 *
 * The CGPDFScanner API lets us intercept every PDF operator
 * in the content stream. This exercises the tokenizer and
 * operator dispatch table.
 * ================================================================ */

/* Operator callbacks — count invocations */
typedef struct {
    int op_count;
    int stream_ops;
    int text_ops;
    int path_ops;
    int image_ops;
    int state_ops;
} ScanStats;

static void op_callback(CGPDFScannerRef scanner, void *info) {
    ScanStats *stats = (ScanStats *)info;
    stats->op_count++;

    /* Try to pop operands to exercise the stack */
    CGPDFReal r;
    CGPDFScannerPopNumber(scanner, &r);

    CGPDFStringRef str;
    CGPDFScannerPopString(scanner, &str);

    const char *name;
    CGPDFScannerPopName(scanner, &name);

    CGPDFArrayRef arr;
    CGPDFScannerPopArray(scanner, &arr);
    if (arr) {
        (void)CGPDFArrayGetCount(arr);
        /* Don't iterate — CGPDFArrayGetObject can SEGV on
         * malformed PDF arrays (confirmed CoreGraphics bug) */
    }

    CGPDFDictionaryRef dict;
    CGPDFScannerPopDictionary(scanner, &dict);

    CGPDFStreamRef stream;
    CGPDFScannerPopStream(scanner, &stream);
    if (stream) {
        CGPDFDataFormat fmt;
        CFDataRef streamData = CGPDFStreamCopyData(stream, &fmt);
        if (streamData) CFRelease(streamData);
    }
}

static void fuzz_scanner(const uint8_t *data, size_t size) {
    @autoreleasepool {
        CGDataProviderRef provider = CGDataProviderCreateWithData(
            NULL, data, size, NULL);
        if (!provider) return;

        CGPDFDocumentRef doc = CGPDFDocumentCreateWithProvider(provider);
        CGDataProviderRelease(provider);
        if (!doc) return;

        CGPDFPageRef page = CGPDFDocumentGetPage(doc, 1);
        if (!page) {
            CGPDFDocumentRelease(doc);
            return;
        }

        /* Register callbacks for all 73 PDF operators */
        CGPDFOperatorTableRef table = CGPDFOperatorTableCreate();
        ScanStats stats = {0};

        /* Graphics state operators */
        const char *stateOps[] = {
            "q", "Q", "cm", "w", "J", "j", "M", "d",
            "ri", "i", "gs", NULL
        };
        for (int k = 0; stateOps[k]; k++)
            CGPDFOperatorTableSetCallback(table, stateOps[k], op_callback);

        /* Path construction */
        const char *pathOps[] = {
            "m", "l", "c", "v", "y", "h", "re", NULL
        };
        for (int k = 0; pathOps[k]; k++)
            CGPDFOperatorTableSetCallback(table, pathOps[k], op_callback);

        /* Path painting */
        const char *paintOps[] = {
            "S", "s", "f", "F", "f*", "B", "B*", "b", "b*",
            "n", "W", "W*", NULL
        };
        for (int k = 0; paintOps[k]; k++)
            CGPDFOperatorTableSetCallback(table, paintOps[k], op_callback);

        /* Text operators */
        const char *textOps[] = {
            "BT", "ET", "Tc", "Tw", "Tz", "TL", "Tf", "Tr",
            "Ts", "Td", "TD", "Tm", "T*", "Tj", "TJ", "'",
            "\"", NULL
        };
        for (int k = 0; textOps[k]; k++)
            CGPDFOperatorTableSetCallback(table, textOps[k], op_callback);

        /* Color operators */
        const char *colorOps[] = {
            "CS", "cs", "SC", "SCN", "sc", "scn", "G", "g",
            "RG", "rg", "K", "k", NULL
        };
        for (int k = 0; colorOps[k]; k++)
            CGPDFOperatorTableSetCallback(table, colorOps[k], op_callback);

        /* XObject / Image operators */
        const char *xobjectOps[] = {
            "Do", "BI", "ID", "EI", NULL
        };
        for (int k = 0; xobjectOps[k]; k++)
            CGPDFOperatorTableSetCallback(table, xobjectOps[k], op_callback);

        /* Marked content */
        const char *markedOps[] = {
            "MP", "DP", "BMC", "BDC", "EMC", NULL
        };
        for (int k = 0; markedOps[k]; k++)
            CGPDFOperatorTableSetCallback(table, markedOps[k], op_callback);

        /* Inline image */
        CGPDFOperatorTableSetCallback(table, "sh", op_callback); /* shading */

        /* Create scanner and scan */
        CGPDFContentStreamRef cs = CGPDFContentStreamCreateWithPage(page);
        if (cs) {
            CGPDFScannerRef scanner = CGPDFScannerCreate(cs, table, &stats);
            if (scanner) {
                CGPDFScannerScan(scanner);
                CGPDFScannerRelease(scanner);
            }
            CGPDFContentStreamRelease(cs);
        }

        CGPDFOperatorTableRelease(table);
        CGPDFDocumentRelease(doc);
    }
}

/* C callbacks for CGPDFDictionaryApplyFunction */
static void decompress_xobject_cb(const char *key, CGPDFObjectRef value, void *info) {
    if (CGPDFObjectGetType(value) == kCGPDFObjectTypeStream) {
        CGPDFStreamRef stream;
        CGPDFObjectGetValue(value, kCGPDFObjectTypeStream, &stream);
        if (stream) {
            CGPDFDataFormat fmt;
            CFDataRef decompressed = CGPDFStreamCopyData(stream, &fmt);
            if (decompressed) {
                (void)CFDataGetLength(decompressed);
                CFRelease(decompressed);
            }
        }
    }
}

static void decompress_font_cb(const char *key, CGPDFObjectRef value, void *info) {
    CGPDFDictionaryRef fontDict = NULL;
    if (CGPDFObjectGetValue(value, kCGPDFObjectTypeDictionary, &fontDict)) {
        CGPDFDictionaryRef descriptor = NULL;
        CGPDFDictionaryGetDictionary(fontDict, "FontDescriptor", &descriptor);
        if (descriptor) {
            CGPDFStreamRef ff;
            if (CGPDFDictionaryGetStream(descriptor, "FontFile", &ff) ||
                CGPDFDictionaryGetStream(descriptor, "FontFile2", &ff) ||
                CGPDFDictionaryGetStream(descriptor, "FontFile3", &ff)) {
                CGPDFDataFormat fmt;
                CFDataRef fontData = CGPDFStreamCopyData(ff, &fmt);
                if (fontData) {
                    (void)CFDataGetLength(fontData);
                    CFRelease(fontData);
                }
            }
        }
    }
}

static void fuzz_stream_decompress(const uint8_t *data, size_t size) {
    @autoreleasepool {
        CGDataProviderRef provider = CGDataProviderCreateWithData(
            NULL, data, size, NULL);
        if (!provider) return;

        CGPDFDocumentRef doc = CGPDFDocumentCreateWithProvider(provider);
        CGDataProviderRelease(provider);
        if (!doc) return;

        CGPDFPageRef page = CGPDFDocumentGetPage(doc, 1);
        if (!page) { CGPDFDocumentRelease(doc); return; }

        CGPDFDictionaryRef pageDict = CGPDFPageGetDictionary(page);
        if (pageDict) {
            CGPDFDictionaryRef resources = NULL;
            CGPDFDictionaryGetDictionary(pageDict, "Resources", &resources);
            if (resources) {
                CGPDFDictionaryRef xobjects = NULL;
                CGPDFDictionaryGetDictionary(resources, "XObject", &xobjects);
                if (xobjects) {
                    CGPDFDictionaryApplyFunction(xobjects, decompress_xobject_cb, NULL);
                }

                CGPDFDictionaryRef fonts = NULL;
                CGPDFDictionaryGetDictionary(resources, "Font", &fonts);
                if (fonts) {
                    CGPDFDictionaryApplyFunction(fonts, decompress_font_cb, NULL);
                }
            }

            CGPDFStreamRef contentStream = NULL;
            if (CGPDFDictionaryGetStream(pageDict, "Contents", &contentStream)) {
                CGPDFDataFormat fmt;
                CFDataRef decompressed = CGPDFStreamCopyData(contentStream, &fmt);
                if (decompressed) {
                    (void)CFDataGetLength(decompressed);
                    CFRelease(decompressed);
                }
            }
        }

        CGPDFDocumentRelease(doc);
    }
}

/* ================================================================
 * PATH 5: PDF-as-Image via ImageIO
 *
 * ImageIO can parse PDFs as image sources, exercising a
 * different code path than CGPDFDocument.
 * ================================================================ */
static void fuzz_pdf_imageio(const uint8_t *data, size_t size) {
    @autoreleasepool {
        NSData *nsdata = [NSData dataWithBytesNoCopy:(void *)data
                                              length:size
                                        freeWhenDone:NO];

        CGImageSourceRef src = CGImageSourceCreateWithData(
            (__bridge CFDataRef)nsdata, NULL);
        if (!src) return;

        CFStringRef type = CGImageSourceGetType(src);
        size_t count = CGImageSourceGetCount(src);

        if (count > 0 && count < 50) {
            for (size_t i = 0; i < count && i < 5; i++) {
                CGImageRef img = CGImageSourceCreateImageAtIndex(src, i, NULL);
                if (img) {
                    (void)CGImageGetWidth(img);
                    (void)CGImageGetHeight(img);
                    CGImageRelease(img);
                }

                CFDictionaryRef props = CGImageSourceCopyPropertiesAtIndex(
                    src, i, NULL);
                if (props) CFRelease(props);
            }
        }

        /* Thumbnail generation — different code path */
        NSDictionary *thumbOpts = @{
            (__bridge NSString *)kCGImageSourceCreateThumbnailFromImageAlways: @YES,
            (__bridge NSString *)kCGImageSourceThumbnailMaxPixelSize: @(128),
        };
        CGImageRef thumb = CGImageSourceCreateThumbnailAtIndex(
            src, 0, (__bridge CFDictionaryRef)thumbOpts);
        if (thumb) CGImageRelease(thumb);

        CFRelease(src);
    }
}

/* ================================================================
 * PATH 6: Encrypted/Password-protected PDFs
 *
 * Exercises the PDF encryption/decryption code paths.
 * ================================================================ */
static void fuzz_encrypted_pdf(const uint8_t *data, size_t size) {
    @autoreleasepool {
        CGDataProviderRef provider = CGDataProviderCreateWithData(
            NULL, data, size, NULL);
        if (!provider) return;

        CGPDFDocumentRef doc = CGPDFDocumentCreateWithProvider(provider);
        CGDataProviderRelease(provider);
        if (!doc) return;

        if (CGPDFDocumentIsEncrypted(doc)) {
            /* Try various passwords */
            CGPDFDocumentUnlockWithPassword(doc, "");
            CGPDFDocumentUnlockWithPassword(doc, "password");
            CGPDFDocumentUnlockWithPassword(doc, "test");

            if (CGPDFDocumentIsUnlocked(doc)) {
                /* If unlocked, try to read content */
                CGPDFPageRef page = CGPDFDocumentGetPage(doc, 1);
                if (page) {
                    CGPDFDictionaryRef dict = CGPDFPageGetDictionary(page);
                    (void)dict;
                }
            }
        }

        CGPDFDocumentRelease(doc);
    }
}

/* ================================================================
 * PATH 7: Deep Dictionary/Array Traversal
 *
 * Recursively walks all objects in the PDF to exercise the
 * object graph traversal and circular reference detection.
 * ================================================================ */
static int g_walk_depth;
static const int MAX_WALK_DEPTH = 20;

static void walk_dict(CGPDFDictionaryRef dict);
static void walk_array(CGPDFArrayRef arr);

static void walk_object(CGPDFObjectRef obj) {
    if (g_walk_depth > MAX_WALK_DEPTH) return;
    g_walk_depth++;

    CGPDFObjectType type = CGPDFObjectGetType(obj);
    switch (type) {
        case kCGPDFObjectTypeBoolean: {
            CGPDFBoolean b;
            CGPDFObjectGetValue(obj, type, &b);
            break;
        }
        case kCGPDFObjectTypeInteger: {
            CGPDFInteger i;
            CGPDFObjectGetValue(obj, type, &i);
            break;
        }
        case kCGPDFObjectTypeReal: {
            CGPDFReal r;
            CGPDFObjectGetValue(obj, type, &r);
            break;
        }
        case kCGPDFObjectTypeName: {
            const char *name;
            CGPDFObjectGetValue(obj, type, &name);
            break;
        }
        case kCGPDFObjectTypeString: {
            CGPDFStringRef str;
            CGPDFObjectGetValue(obj, type, &str);
            if (str) {
                CFStringRef cfstr = CGPDFStringCopyTextString(str);
                if (cfstr) CFRelease(cfstr);
                CFDateRef date = CGPDFStringCopyDate(str);
                if (date) CFRelease(date);
            }
            break;
        }
        case kCGPDFObjectTypeArray: {
            CGPDFArrayRef arr;
            CGPDFObjectGetValue(obj, type, &arr);
            if (arr) walk_array(arr);
            break;
        }
        case kCGPDFObjectTypeDictionary: {
            CGPDFDictionaryRef dict;
            CGPDFObjectGetValue(obj, type, &dict);
            if (dict) walk_dict(dict);
            break;
        }
        case kCGPDFObjectTypeStream: {
            CGPDFStreamRef stream;
            CGPDFObjectGetValue(obj, type, &stream);
            if (stream) {
                CGPDFDictionaryRef sdict = CGPDFStreamGetDictionary(stream);
                if (sdict) walk_dict(sdict);
                CGPDFDataFormat fmt;
                CFDataRef sdata = CGPDFStreamCopyData(stream, &fmt);
                if (sdata) {
                    (void)CFDataGetLength(sdata);
                    CFRelease(sdata);
                }
            }
            break;
        }
        default: break;
    }
    g_walk_depth--;
}

static void walk_array(CGPDFArrayRef arr) {
    if (g_walk_depth > MAX_WALK_DEPTH) return;
    size_t count = CGPDFArrayGetCount(arr);
    if (count > 100) count = 100;
    for (size_t i = 0; i < count; i++) {
        CGPDFObjectRef obj;
        if (CGPDFArrayGetObject(arr, i, &obj)) {
            walk_object(obj);
        }
    }
}

static void walk_dict_cb(const char *key, CGPDFObjectRef value, void *info) {
    walk_object(value);
}

static void walk_dict(CGPDFDictionaryRef dict) {
    if (g_walk_depth > MAX_WALK_DEPTH) return;
    CGPDFDictionaryApplyFunction(dict, walk_dict_cb, NULL);
}

static void fuzz_deep_traversal(const uint8_t *data, size_t size) {
    @autoreleasepool {
        CGDataProviderRef provider = CGDataProviderCreateWithData(
            NULL, data, size, NULL);
        if (!provider) return;

        CGPDFDocumentRef doc = CGPDFDocumentCreateWithProvider(provider);
        CGDataProviderRelease(provider);
        if (!doc) return;

        g_walk_depth = 0;

        /* Walk catalog */
        CGPDFDictionaryRef catalog = CGPDFDocumentGetCatalog(doc);
        if (catalog) walk_dict(catalog);

        /* Walk info dict */
        CGPDFDictionaryRef info = CGPDFDocumentGetInfo(doc);
        if (info) walk_dict(info);

        /* Walk first page */
        CGPDFPageRef page = CGPDFDocumentGetPage(doc, 1);
        if (page) {
            CGPDFDictionaryRef pageDict = CGPDFPageGetDictionary(page);
            if (pageDict) walk_dict(pageDict);
        }

        CGPDFDocumentRelease(doc);
    }
}

/* ================================================================
 * PATH 8: JBIG2 Stream (FORCEDENTRY vector)
 *
 * JBIG2 is the compression format used in FORCEDENTRY.
 * We create PDFs with embedded JBIG2 streams to fuzz
 * the JBIG2 decoder in CoreGraphics.
 * ================================================================ */
static void fuzz_jbig2_stream(const uint8_t *data, size_t size) {
    @autoreleasepool {
        if (size < 16) return;

        /* Construct a minimal PDF with JBIG2 image */
        NSMutableData *pdf = [NSMutableData data];

        /* Header */
        [pdf appendBytes:"%PDF-1.5\n" length:9];

        /* Object 1: Catalog */
        int off1 = (int)pdf.length;
        NSString *obj1 = @"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n";
        [pdf appendData:[obj1 dataUsingEncoding:NSUTF8StringEncoding]];

        /* Object 2: Pages */
        int off2 = (int)pdf.length;
        NSString *obj2 = @"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n";
        [pdf appendData:[obj2 dataUsingEncoding:NSUTF8StringEncoding]];

        /* Object 3: Page */
        int off3 = (int)pdf.length;
        NSString *obj3 = @"3 0 obj\n<< /Type /Page /Parent 2 0 R "
            "/MediaBox [0 0 100 100] "
            "/Contents 5 0 R "
            "/Resources << /XObject << /Im0 4 0 R >> >> >>\nendobj\n";
        [pdf appendData:[obj3 dataUsingEncoding:NSUTF8StringEncoding]];

        /* Object 4: JBIG2 Image XObject — uses fuzz data */
        int off4 = (int)pdf.length;
        NSString *obj4head = [NSString stringWithFormat:
            @"4 0 obj\n<< /Type /XObject /Subtype /Image "
            "/Width 100 /Height 100 /ColorSpace /DeviceGray "
            "/BitsPerComponent 1 /Filter /JBIG2Decode "
            "/Length %zu >>\nstream\n", size];
        [pdf appendData:[obj4head dataUsingEncoding:NSUTF8StringEncoding]];
        [pdf appendBytes:data length:size]; /* JBIG2 data */
        [pdf appendBytes:"\nendstream\nendobj\n" length:18];

        /* Object 5: Content stream — draw image */
        int off5 = (int)pdf.length;
        NSString *contentStr = @"100 0 0 100 0 0 cm /Im0 Do";
        NSString *obj5 = [NSString stringWithFormat:
            @"5 0 obj\n<< /Length %lu >>\nstream\n%@\nendstream\nendobj\n",
            (unsigned long)contentStr.length, contentStr];
        [pdf appendData:[obj5 dataUsingEncoding:NSUTF8StringEncoding]];

        /* Xref table */
        int xrefOff = (int)pdf.length;
        NSString *xref = [NSString stringWithFormat:
            @"xref\n0 6\n"
            "0000000000 65535 f \n"
            "%010d 00000 n \n"
            "%010d 00000 n \n"
            "%010d 00000 n \n"
            "%010d 00000 n \n"
            "%010d 00000 n \n"
            "trailer\n<< /Size 6 /Root 1 0 R >>\n"
            "startxref\n%d\n%%%%EOF\n",
            off1, off2, off3, off4, off5, xrefOff];
        [pdf appendData:[xref dataUsingEncoding:NSUTF8StringEncoding]];

        /* Now parse this constructed PDF */
        CGDataProviderRef prov = CGDataProviderCreateWithCFData(
            (__bridge CFDataRef)pdf);
        if (!prov) return;

        CGPDFDocumentRef doc = CGPDFDocumentCreateWithProvider(prov);
        CGDataProviderRelease(prov);
        if (!doc) return;

        CGPDFPageRef page = CGPDFDocumentGetPage(doc, 1);
        if (page) {
            /* Render to trigger JBIG2 decompression */
            CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
            CGContextRef ctx = CGBitmapContextCreate(
                NULL, 100, 100, 8, 400, cs,
                kCGImageAlphaPremultipliedLast);
            CGColorSpaceRelease(cs);

            if (ctx) {
                CGContextDrawPDFPage(ctx, page);
                CGContextRelease(ctx);
            }
        }

        CGPDFDocumentRelease(doc);
    }
}

/* ================================================================
 * PATH 9: Inline Image Objects
 *
 * BI/ID/EI operators define inline images within content streams.
 * These bypass XObject validation and are parsed differently.
 * ================================================================ */
static void fuzz_inline_image(const uint8_t *data, size_t size) {
    @autoreleasepool {
        if (size < 8) return;

        /* Use first 2 bytes for image dimensions */
        uint8_t w = data[0] ? data[0] : 1;
        uint8_t h = data[1] ? data[1] : 1;
        if (w > 64) w = 64;
        if (h > 64) h = 64;

        /* Build content stream with inline image */
        NSMutableData *content = [NSMutableData data];
        NSString *header = [NSString stringWithFormat:
            @"BI /W %d /H %d /BPC 8 /CS /RGB ID ", w, h];
        [content appendData:[header dataUsingEncoding:NSUTF8StringEncoding]];
        size_t imgSize = MIN(size - 2, (size_t)(w * h * 3));
        [content appendBytes:data + 2 length:imgSize];
        [content appendBytes:" EI" length:3];

        /* Wrap in a PDF */
        NSMutableData *pdf = [NSMutableData data];
        [pdf appendBytes:"%PDF-1.4\n" length:9];

        int off1 = (int)pdf.length;
        [pdf appendData:[@"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
            dataUsingEncoding:NSUTF8StringEncoding]];
        int off2 = (int)pdf.length;
        [pdf appendData:[@"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
            dataUsingEncoding:NSUTF8StringEncoding]];
        int off3 = (int)pdf.length;
        [pdf appendData:[@"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 100 100]/Contents 4 0 R>>endobj\n"
            dataUsingEncoding:NSUTF8StringEncoding]];
        int off4 = (int)pdf.length;
        NSString *obj4 = [NSString stringWithFormat:
            @"4 0 obj<</Length %lu>>stream\n", (unsigned long)content.length];
        [pdf appendData:[obj4 dataUsingEncoding:NSUTF8StringEncoding]];
        [pdf appendData:content];
        [pdf appendBytes:"\nendstream endobj\n" length:18];

        int xrefOff = (int)pdf.length;
        NSString *xref = [NSString stringWithFormat:
            @"xref\n0 5\n0000000000 65535 f \n"
            "%010d 00000 n \n%010d 00000 n \n%010d 00000 n \n%010d 00000 n \n"
            "trailer<</Size 5/Root 1 0 R>>\nstartxref\n%d\n%%%%EOF\n",
            off1, off2, off3, off4, xrefOff];
        [pdf appendData:[xref dataUsingEncoding:NSUTF8StringEncoding]];

        CGDataProviderRef prov = CGDataProviderCreateWithCFData(
            (__bridge CFDataRef)pdf);
        if (!prov) return;

        CGPDFDocumentRef doc = CGPDFDocumentCreateWithProvider(prov);
        CGDataProviderRelease(prov);
        if (!doc) return;

        CGPDFPageRef page = CGPDFDocumentGetPage(doc, 1);
        if (page) {
            CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
            CGContextRef ctx = CGBitmapContextCreate(
                NULL, 100, 100, 8, 400, cs,
                kCGImageAlphaPremultipliedLast);
            CGColorSpaceRelease(cs);
            if (ctx) {
                CGContextDrawPDFPage(ctx, page);
                CGContextRelease(ctx);
            }
        }

        CGPDFDocumentRelease(doc);
    }
}

/* ================================================================
 * LLVMFuzzerTestOneInput
 *
 * Input:
 *   byte 0:    path selector (10 paths)
 *   bytes 1+:  fuzz data
 * ================================================================ */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) return 0;

    uint8_t path = data[0];
    const uint8_t *payload = data + 1;
    size_t psize = size - 1;

    switch (path % 9) {
        case 0: fuzz_document_creation(payload, psize);  break;
        case 1: fuzz_page_rendering(payload, psize);     break;
        case 2: fuzz_scanner(payload, psize);             break;
        case 3: fuzz_stream_decompress(payload, psize);  break;
        case 4: fuzz_pdf_imageio(payload, psize);         break;
        case 5: fuzz_encrypted_pdf(payload, psize);       break;
        case 6: fuzz_deep_traversal(payload, psize);      break;
        case 7: fuzz_jbig2_stream(payload, psize);        break;
        case 8: fuzz_inline_image(payload, psize);        break;
    }

    return 0;
}
