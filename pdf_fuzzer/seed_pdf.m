/*
 * seed_pdf.m — Generate seeds for 9 CoreGraphics PDF fuzzing paths
 *
 * Build: clang -framework Foundation -framework CoreGraphics -o seed_pdf seed_pdf.m
 * Run:   ./seed_pdf corpus/
 */
#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>

static void write_seed(const char *dir, const char *name,
                       uint8_t path_id, NSData *payload) {
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s/%s", dir, name);
    NSMutableData *full = [NSMutableData dataWithBytes:&path_id length:1];
    [full appendData:payload];
    [full writeToFile:[NSString stringWithUTF8String:filepath] atomically:YES];
    printf("  [+] %-44s (%5lu bytes, path=%d)\n", name,
           (unsigned long)full.length, path_id);
}

/* Create a well-formed minimal PDF that exercises the given feature */
static NSData *make_pdf(NSString *content, NSDictionary *extra) {
    NSMutableData *pdf = [NSMutableData data];

    [pdf appendBytes:"%PDF-1.7\n" length:9];

    /* Object 1: Catalog */
    int off1 = (int)pdf.length;
    NSMutableString *catalog = [NSMutableString stringWithString:
        @"1 0 obj\n<< /Type /Catalog /Pages 2 0 R"];
    if (extra[@"catalog"]) [catalog appendFormat:@" %@", extra[@"catalog"]];
    [catalog appendString:@" >>\nendobj\n"];
    [pdf appendData:[catalog dataUsingEncoding:NSUTF8StringEncoding]];

    /* Object 2: Pages */
    int off2 = (int)pdf.length;
    [pdf appendData:[@"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        dataUsingEncoding:NSUTF8StringEncoding]];

    /* Object 3: Page with resources */
    int off3 = (int)pdf.length;
    NSMutableString *page = [NSMutableString stringWithString:
        @"3 0 obj\n<< /Type /Page /Parent 2 0 R "
        "/MediaBox [0 0 612 792] /Contents 4 0 R"];
    if (extra[@"resources"]) {
        [page appendFormat:@" /Resources %@", extra[@"resources"]];
    } else {
        [page appendString:@" /Resources << >>"];
    }
    [page appendString:@" >>\nendobj\n"];
    [pdf appendData:[page dataUsingEncoding:NSUTF8StringEncoding]];

    /* Object 4: Content stream */
    int off4 = (int)pdf.length;
    NSData *contentData = [content dataUsingEncoding:NSUTF8StringEncoding];
    NSString *obj4 = [NSString stringWithFormat:
        @"4 0 obj\n<< /Length %lu >>\nstream\n",
        (unsigned long)contentData.length];
    [pdf appendData:[obj4 dataUsingEncoding:NSUTF8StringEncoding]];
    [pdf appendData:contentData];
    [pdf appendBytes:"\nendstream\nendobj\n" length:18];

    /* Additional objects */
    NSMutableArray *offsets = [NSMutableArray array];
    int nextObj = 5;
    if (extra[@"objects"]) {
        for (NSString *obj in extra[@"objects"]) {
            [offsets addObject:@((int)pdf.length)];
            NSString *full = [NSString stringWithFormat:@"%d 0 obj\n%@\nendobj\n",
                              nextObj++, obj];
            [pdf appendData:[full dataUsingEncoding:NSUTF8StringEncoding]];
        }
    }

    /* Xref table */
    int xrefOff = (int)pdf.length;
    NSMutableString *xref = [NSMutableString stringWithFormat:
        @"xref\n0 %d\n0000000000 65535 f \n"
        "%010d 00000 n \n%010d 00000 n \n%010d 00000 n \n%010d 00000 n \n",
        nextObj, off1, off2, off3, off4];
    for (NSNumber *off in offsets) {
        [xref appendFormat:@"%010d 00000 n \n", [off intValue]];
    }
    [xref appendFormat:@"trailer\n<< /Size %d /Root 1 0 R", nextObj];
    if (extra[@"info"]) [xref appendFormat:@" /Info %@ 0 R", extra[@"info"]];
    [xref appendFormat:@" >>\nstartxref\n%d\n%%%%EOF\n", xrefOff];
    [pdf appendData:[xref dataUsingEncoding:NSUTF8StringEncoding]];

    return pdf;
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        const char *dir = argc > 1 ? argv[1] : "corpus";
        mkdir(dir, 0755);
        printf("[*] Generating PDF seeds in %s/\n\n", dir);

        /* PATH 0: Document creation — minimal PDF */
        {
            NSData *pdf = make_pdf(@"", @{});
            write_seed(dir, "doc_minimal.bin", 0, pdf);
        }

        /* PATH 0: Document with info dict */
        {
            NSData *pdf = make_pdf(@"BT /F1 12 Tf 100 700 Td (Hello) Tj ET", @{
                @"info": @"5",
                @"objects": @[@"<< /Title (Fuzz Test) /Author (Fuzzer) "
                    "/CreationDate (D:20260329120000) >>"],
            });
            write_seed(dir, "doc_with_info.bin", 0, pdf);
        }

        /* PATH 1: Page rendering — text and paths */
        {
            NSData *pdf = make_pdf(
                @"q 1 0 0 1 50 700 cm "
                "BT /F1 24 Tf (Rendering Test) Tj ET Q "
                "100 600 m 200 600 l 200 500 l 100 500 l h "
                "0.5 0 0 RG 2 w S "
                "0 0 1 rg 150 400 50 50 re f ",
                @{@"resources": @"<< /Font << /F1 5 0 R >> >>",
                  @"objects": @[@"<< /Type /Font /Subtype /Type1 "
                      "/BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"]});
            write_seed(dir, "page_text_path.bin", 1, pdf);
        }

        /* PATH 1: Complex graphics */
        {
            NSData *pdf = make_pdf(
                @"q 0.8 0 0 0.8 0 0 cm "
                "0 0 612 792 re W n "
                "50 700 m 100 750 150 750 200 700 c "
                "250 650 300 650 350 700 c S "
                "q 200 400 m 250 500 l 300 400 l h "
                "1 0 0 rg f Q "
                "0.5 G 10 w 1 J 1 j "
                "100 300 m 200 300 300 400 v S Q",
                @{});
            write_seed(dir, "page_complex_gfx.bin", 1, pdf);
        }

        /* PATH 2: Scanner — many operators */
        {
            NSData *pdf = make_pdf(
                @"q 1 0 0 RG 2 w "
                "100 700 m 200 700 l S "
                "100 680 m 200 680 300 720 v S "
                "0 0 1 rg 50 600 100 50 re f "
                "BT /F1 16 Tf 1 0 0 1 100 500 Tm "
                "(Test) Tj T* (Line2) Tj ET "
                "0.3 0.6 0.9 rg 200 400 m 250 450 l 300 400 l h f* Q",
                @{@"resources": @"<< /Font << /F1 5 0 R >> >>",
                  @"objects": @[@"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>"]});
            write_seed(dir, "scanner_many_ops.bin", 2, pdf);
        }

        /* PATH 3: Stream decompression — FlateDecode */
        {
            /* Create a FlateDecoded content stream manually */
            NSString *raw = @"BT /F1 12 Tf 100 700 Td (Compressed) Tj ET";
            NSData *rawData = [raw dataUsingEncoding:NSUTF8StringEncoding];

            NSMutableData *pdf = [NSMutableData data];
            [pdf appendBytes:"%PDF-1.5\n" length:9];
            int o1 = (int)pdf.length;
            [pdf appendData:[@"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
                dataUsingEncoding:NSUTF8StringEncoding]];
            int o2 = (int)pdf.length;
            [pdf appendData:[@"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
                dataUsingEncoding:NSUTF8StringEncoding]];
            int o3 = (int)pdf.length;
            [pdf appendData:[@"3 0 obj<</Type/Page/Parent 2 0 R"
                "/MediaBox[0 0 612 792]/Contents 4 0 R"
                "/Resources<</Font<</F1 5 0 R>>>>>>endobj\n"
                dataUsingEncoding:NSUTF8StringEncoding]];

            /* Deflate the content */
            NSData *compressed = [rawData compressedDataUsingAlgorithm:
                NSDataCompressionAlgorithmZlib error:NULL];
            int o4 = (int)pdf.length;
            NSString *s4 = [NSString stringWithFormat:
                @"4 0 obj<</Filter/FlateDecode/Length %lu>>stream\n",
                (unsigned long)(compressed ? compressed.length : rawData.length)];
            [pdf appendData:[s4 dataUsingEncoding:NSUTF8StringEncoding]];
            [pdf appendData:compressed ?: rawData];
            [pdf appendBytes:"\nendstream endobj\n" length:18];

            int o5 = (int)pdf.length;
            [pdf appendData:[@"5 0 obj<</Type/Font/Subtype/Type1"
                "/BaseFont/Helvetica>>endobj\n"
                dataUsingEncoding:NSUTF8StringEncoding]];

            int xo = (int)pdf.length;
            NSString *xr = [NSString stringWithFormat:
                @"xref\n0 6\n0000000000 65535 f \n"
                "%010d 00000 n \n%010d 00000 n \n%010d 00000 n \n"
                "%010d 00000 n \n%010d 00000 n \n"
                "trailer<</Size 6/Root 1 0 R>>\nstartxref\n%d\n%%%%EOF\n",
                o1, o2, o3, o4, o5, xo];
            [pdf appendData:[xr dataUsingEncoding:NSUTF8StringEncoding]];

            write_seed(dir, "stream_flate.bin", 3, pdf);
        }

        /* PATH 4: PDF via ImageIO */
        {
            NSData *pdf = make_pdf(
                @"0 0 1 rg 0 0 612 792 re f "
                "1 1 1 rg BT /F1 48 Tf 100 400 Td (ImageIO) Tj ET",
                @{@"resources": @"<< /Font << /F1 5 0 R >> >>",
                  @"objects": @[@"<< /Type /Font /Subtype /Type1 /BaseFont /Times-Bold >>"]});
            write_seed(dir, "imageio_pdf.bin", 4, pdf);
        }

        /* PATH 5: Encrypted PDF (RC4 40-bit, empty password) */
        {
            /* Create via CGPDFContext with encrypt dict */
            NSMutableData *pdfData = [NSMutableData data];
            CGDataConsumerRef consumer = CGDataConsumerCreateWithCFData(
                (__bridge CFMutableDataRef)pdfData);
            if (consumer) {
                NSDictionary *auxInfo = @{
                    (__bridge NSString *)kCGPDFContextOwnerPassword: @"test",
                    (__bridge NSString *)kCGPDFContextUserPassword: @"",
                };
                CGRect mediaBox = CGRectMake(0, 0, 200, 200);
                CGContextRef ctx = CGPDFContextCreate(consumer, &mediaBox,
                    (__bridge CFDictionaryRef)auxInfo);
                if (ctx) {
                    CGPDFContextBeginPage(ctx, NULL);
                    CGContextSetRGBFillColor(ctx, 1, 0, 0, 1);
                    CGContextFillRect(ctx, CGRectMake(10, 10, 180, 180));
                    CGPDFContextEndPage(ctx);
                    CGPDFContextClose(ctx);
                    CGContextRelease(ctx);
                }
                CGDataConsumerRelease(consumer);
            }
            if (pdfData.length > 0)
                write_seed(dir, "encrypted_pdf.bin", 5, pdfData);
        }

        /* PATH 6: Deep traversal — nested dictionaries */
        {
            NSData *pdf = make_pdf(@"", @{
                @"catalog": @"/Names << /EmbeddedFiles << /Names [(test) 5 0 R] >> >> "
                    "/Outlines 6 0 R",
                @"objects": @[
                    @"<< /Type /Filespec /F (embedded.txt) /EF << /F 7 0 R >> >>",
                    @"<< /Type /Outlines /Count 1 /First 8 0 R >>",
                    @"<< /Type /EmbeddedFile /Length 5 >>stream\nhello\nendstream",
                    @"<< /Title (Bookmark) /Parent 6 0 R /Dest [3 0 R /Fit] >>",
                ],
            });
            write_seed(dir, "deep_nested.bin", 6, pdf);
        }

        /* PATH 7: JBIG2 stream — minimal JBIG2 header */
        {
            /* JBIG2 file header + segment data */
            uint8_t jbig2[] = {
                0x97, 0x4A, 0x42, 0x32, /* JBIG2 signature */
                0x0D, 0x0A, 0x1A, 0x0A, /* file header */
                0x01,                     /* flags: sequential */
                0x00, 0x00, 0x00, 0x01,  /* number of pages: 1 */
                /* Segment 0: symbol dictionary */
                0x00, 0x00, 0x00, 0x00,  /* segment number */
                0x00,                     /* flags */
                0x00,                     /* referred count */
                0x00, 0x00, 0x00, 0x01,  /* page association */
                0x00, 0x00, 0x00, 0x04,  /* data length */
                0x00, 0x00, 0x00, 0x00,  /* data */
            };
            write_seed(dir, "jbig2_minimal.bin", 7,
                [NSData dataWithBytes:jbig2 length:sizeof(jbig2)]);
        }

        /* PATH 8: Inline image */
        {
            /* Build a PDF with inline image content */
            uint8_t pixels[64 * 3]; /* 8x8 RGB */
            for (int i = 0; i < 64 * 3; i++) pixels[i] = i & 0xFF;

            NSMutableString *content = [NSMutableString stringWithString:
                @"q 64 0 0 64 50 700 cm BI /W 8 /H 8 /BPC 8 /CS /RGB ID "];
            NSMutableData *contentData = [NSMutableData data];
            [contentData appendData:[content dataUsingEncoding:NSUTF8StringEncoding]];
            [contentData appendBytes:pixels length:sizeof(pixels)];
            [contentData appendBytes:" EI Q\n" length:6];

            /* Prepend path_id byte to raw content for inline image path */
            write_seed(dir, "inline_image.bin", 8, contentData);
        }

        /* Bonus: A valid PDF with raw byte data for maximum fuzz potential */
        {
            NSData *pdf = make_pdf(@"", @{});
            write_seed(dir, "raw_pdf_template.bin", 0, pdf);
        }

        printf("\n[+] PDF seeds generated for 9 paths.\n");
        return 0;
    }
}
