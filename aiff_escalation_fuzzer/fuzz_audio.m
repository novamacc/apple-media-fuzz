/*
 * fuzz_audio.m — God-Level AudioToolbox Multi-Format Fuzzer for macOS
 *
 * ═══════════════════════════════════════════════════════════════════════
 * TARGET: AudioToolbox.framework + CoreAudio
 *
 * Escalates from existing AIFF DoS (Report 3) to find MEMORY CORRUPTION
 * across ALL audio formats parsed by AudioToolbox.
 *
 * ZERO-CLICK VECTORS:
 *   - QuickLook/Spotlight: Indexing audio files triggers parsing (zero-click!)
 *   - Safari: Web Audio API decodes audio data
 *   - Mail: Audio attachments auto-previewed
 *   - iMessage: Audio messages auto-decoded
 *   - AirDrop: Received audio files auto-preview
 *
 * FORMAT COVERAGE (10 formats):
 *   [1]  AIFF   - Apple Interchange File Format (known DoS here)
 *   [2]  AIFC   - Compressed AIFF variant
 *   [3]  WAV    - RIFF/WAVE (PCM, compressed)
 *   [4]  CAF    - Core Audio Format (Apple's modern container)
 *   [5]  MP3    - MPEG Layer III
 *   [6]  AAC    - Advanced Audio Coding (ADTS/raw)
 *   [7]  FLAC   - Free Lossless Audio Codec
 *   [8]  AU     - Sun/NeXT audio format
 *   [9]  AMR    - Adaptive Multi-Rate (telephony)
 *   [10] MIDI   - Musical Instrument Digital Interface
 *
 * PARSING STRATEGIES:
 *   [A] Stream parsing   - AudioFileStreamParseBytes (fragmented)
 *   [B] File-based       - ExtAudioFileOpenURL with full decode
 *   [C] Memory-based     - AudioFileOpenWithCallbacks (in-memory)
 *
 * Build:
 *   clang -framework AudioToolbox -framework CoreFoundation \
 *         -framework Foundation \
 *         -fsanitize=fuzzer,address,undefined -g -O1 \
 *         -o fuzz_audio fuzz_audio.m
 *
 * Run:
 *   ./fuzz_audio corpus/ -max_len=65536 -timeout=5
 * ═══════════════════════════════════════════════════════════════════════
 */

#import <AudioToolbox/AudioToolbox.h>
#import <Foundation/Foundation.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ── Audio file format magic headers ── */
static const uint8_t AIFF_MAGIC[]  = { 'F','O','R','M', 0,0,0,0, 'A','I','F','F' };
static const uint8_t AIFC_MAGIC[]  = { 'F','O','R','M', 0,0,0,0, 'A','I','F','C' };
static const uint8_t WAV_MAGIC[]   = { 'R','I','F','F', 0,0,0,0, 'W','A','V','E' };
static const uint8_t CAF_MAGIC[]   = { 'c','a','f','f', 0,0,0,1 };
static const uint8_t AU_MAGIC[]    = { '.','s','n','d' };
static const uint8_t FLAC_MAGIC[]  = { 'f','L','a','C' };
static const uint8_t MIDI_MAGIC[]  = { 'M','T','h','d' };

/* ── Callbacks ── */
static void prop_cb(void *ud, AudioFileStreamID s,
                    AudioFileStreamPropertyID pid,
                    AudioFileStreamPropertyFlags *f) {
    /* Exercise property reads to trigger parser code paths */
    if (pid == kAudioFileStreamProperty_DataFormat) {
        AudioStreamBasicDescription asbd;
        UInt32 sz = sizeof(asbd);
        AudioFileStreamGetProperty(s, pid, &sz, &asbd);
    } else if (pid == kAudioFileStreamProperty_MagicCookieData) {
        UInt32 sz = 0;
        Boolean writable;
        AudioFileStreamGetPropertyInfo(s, pid, &sz, &writable);
        if (sz > 0 && sz < 65536) {
            void *cookie = malloc(sz);
            if (cookie) {
                AudioFileStreamGetProperty(s, pid, &sz, cookie);
                free(cookie);
            }
        }
    } else if (pid == kAudioFileStreamProperty_FormatList) {
        UInt32 sz = 0;
        Boolean writable;
        AudioFileStreamGetPropertyInfo(s, pid, &sz, &writable);
        if (sz > 0 && sz < 65536) {
            void *list = malloc(sz);
            if (list) {
                AudioFileStreamGetProperty(s, pid, &sz, list);
                free(list);
            }
        }
    } else if (pid == kAudioFileStreamProperty_PacketSizeUpperBound ||
               pid == kAudioFileStreamProperty_AverageBytesPerPacket ||
               pid == kAudioFileStreamProperty_BitRate) {
        UInt32 val = 0;
        UInt32 sz = sizeof(val);
        AudioFileStreamGetProperty(s, pid, &sz, &val);
    }
}

static void pkt_cb(void *ud, UInt32 nb, UInt32 np,
                   const void *d, AudioStreamPacketDescription *pd) {
    /* Touch packet descriptions to trigger copy/validation */
    if (pd && np > 0) {
        for (UInt32 i = 0; i < np && i < 256; i++) {
            (void)pd[i].mStartOffset;
            (void)pd[i].mDataByteSize;
            (void)pd[i].mVariableFramesInPacket;
        }
    }
}

/* ── Memory-based file callbacks (for AudioFileOpenWithCallbacks) ── */
typedef struct {
    const uint8_t *data;
    size_t size;
    SInt64 pos;
} MemFile;

static OSStatus mem_read(void *inClientData, SInt64 inPosition,
                         UInt32 requestCount, void *buffer,
                         UInt32 *actualCount) {
    MemFile *mf = (MemFile *)inClientData;
    if (inPosition < 0 || (size_t)inPosition >= mf->size) {
        *actualCount = 0;
        return kAudioFilePositionError;
    }
    UInt32 avail = (UInt32)(mf->size - (size_t)inPosition);
    UInt32 toRead = requestCount < avail ? requestCount : avail;
    memcpy(buffer, mf->data + inPosition, toRead);
    *actualCount = toRead;
    return noErr;
}

static SInt64 mem_getsize(void *inClientData) {
    return ((MemFile *)inClientData)->size;
}

/* ================================================================
 * STRATEGY A: Stream Parsing (AudioFileStreamParseBytes)
 *
 * Feeds data in fragments to the streaming audio parser.
 * This is the path used by Safari's Web Audio, AirPlay, etc.
 * Fragment sizes stress boundary handling in the parser.
 * ================================================================ */
static void fuzz_stream_parse(const uint8_t *header, size_t hdr_len,
                              AudioFileTypeID fileType,
                              const uint8_t *data, size_t size,
                              uint8_t strategy) {
    /* Build: header + fuzz data */
    size_t total = hdr_len + size;
    uint8_t *input = malloc(total);
    if (!input) return;

    memcpy(input, header, hdr_len);
    memcpy(input + hdr_len, data, size);

    /* Patch size field for FORM/RIFF containers */
    if (hdr_len >= 12 && (memcmp(header, "FORM", 4) == 0 ||
                          memcmp(header, "RIFF", 4) == 0)) {
        uint32_t bodySize = (uint32_t)(total - 8);
        if (memcmp(header, "RIFF", 4) == 0) {
            /* Little-endian for WAV */
            input[4] = bodySize & 0xFF;
            input[5] = (bodySize >> 8) & 0xFF;
            input[6] = (bodySize >> 16) & 0xFF;
            input[7] = (bodySize >> 24) & 0xFF;
        } else {
            /* Big-endian for AIFF */
            input[4] = (bodySize >> 24) & 0xFF;
            input[5] = (bodySize >> 16) & 0xFF;
            input[6] = (bodySize >> 8) & 0xFF;
            input[7] = bodySize & 0xFF;
        }
    }

    AudioFileStreamID stream = NULL;
    OSStatus st = AudioFileStreamOpen(NULL, prop_cb, pkt_cb, fileType, &stream);
    if (st != noErr || !stream) { free(input); return; }

    /* Fragment strategy */
    size_t frag;
    if (strategy < 0x20)      frag = 1;
    else if (strategy < 0x40) frag = 2;
    else if (strategy < 0x60) frag = 4;
    else if (strategy < 0x80) frag = 8;
    else if (strategy < 0xA0) frag = 32;
    else if (strategy < 0xC0) frag = 128;
    else if (strategy < 0xE0) frag = 512;
    else                      frag = total;

    size_t off = 0;
    int iters = 0;
    while (off < total && iters < 50000) {
        size_t chunk = frag;
        if (off + chunk > total) chunk = total - off;
        st = AudioFileStreamParseBytes(stream, (UInt32)chunk, input + off, 0);
        if (st != noErr && st != kAudioFileStreamError_NotOptimized &&
            st != kAudioFileStreamError_UnsupportedDataFormat &&
            st != kAudioFileStreamError_UnsupportedProperty) break;
        off += chunk;
        iters++;
    }

    AudioFileStreamClose(stream);
    free(input);
}

/* ================================================================
 * STRATEGY B: File-Based Parsing (ExtAudioFileOpenURL)
 *
 * Writes fuzz data to a temp file and opens with ExtAudioFile API.
 * This triggers the full file-based parser path including:
 *   - Format detection from file content
 *   - Codec initialization
 *   - Full audio decode attempt
 *   - Channel layout parsing
 * ================================================================ */
static void fuzz_file_parse(const uint8_t *header, size_t hdr_len,
                            const uint8_t *data, size_t size,
                            const char *ext) {
    @autoreleasepool {
        /* Write to temp file */
        char tmppath[256];
        snprintf(tmppath, sizeof(tmppath), "/tmp/fuzz_audio_%d.%s", getpid(), ext);

        FILE *f = fopen(tmppath, "wb");
        if (!f) return;
        fwrite(header, 1, hdr_len, f);
        fwrite(data, 1, size, f);
        fclose(f);

        NSString *path = [NSString stringWithUTF8String:tmppath];
        NSURL *url = [NSURL fileURLWithPath:path];

        /* Open with ExtAudioFile (triggers full decode pipeline) */
        ExtAudioFileRef extFile = NULL;
        OSStatus st = ExtAudioFileOpenURL((__bridge CFURLRef)url, &extFile);

        if (st == noErr && extFile) {
            /* Get the file's format */
            AudioStreamBasicDescription fileFormat;
            UInt32 sz = sizeof(fileFormat);
            st = ExtAudioFileGetProperty(extFile,
                kExtAudioFileProperty_FileDataFormat, &sz, &fileFormat);

            if (st == noErr) {
                /* Set client format to PCM (forces decode) */
                AudioStreamBasicDescription clientFormat = {0};
                clientFormat.mSampleRate = fileFormat.mSampleRate;
                if (clientFormat.mSampleRate <= 0 ||
                    clientFormat.mSampleRate > 192000)
                    clientFormat.mSampleRate = 44100;
                clientFormat.mFormatID = kAudioFormatLinearPCM;
                clientFormat.mFormatFlags =
                    kAudioFormatFlagIsFloat | kAudioFormatFlagIsPacked;
                clientFormat.mBitsPerChannel = 32;
                clientFormat.mChannelsPerFrame =
                    fileFormat.mChannelsPerFrame > 0 ?
                    fileFormat.mChannelsPerFrame : 1;
                if (clientFormat.mChannelsPerFrame > 8)
                    clientFormat.mChannelsPerFrame = 2;
                clientFormat.mBytesPerFrame =
                    clientFormat.mChannelsPerFrame * 4;
                clientFormat.mFramesPerPacket = 1;
                clientFormat.mBytesPerPacket = clientFormat.mBytesPerFrame;

                st = ExtAudioFileSetProperty(extFile,
                    kExtAudioFileProperty_ClientDataFormat,
                    sizeof(clientFormat), &clientFormat);

                if (st == noErr) {
                    /* Read decoded audio (max 8192 frames) */
                    float buf[8192 * 8];  /* 8 channels max */
                    AudioBufferList abl;
                    abl.mNumberBuffers = 1;
                    abl.mBuffers[0].mNumberChannels =
                        clientFormat.mChannelsPerFrame;
                    abl.mBuffers[0].mDataByteSize = sizeof(buf);
                    abl.mBuffers[0].mData = buf;

                    UInt32 frames = 8192;
                    st = ExtAudioFileRead(extFile, &frames, &abl);
                    /* Don't care about errors — we're fuzzing */
                }
            }

            ExtAudioFileDispose(extFile);
        }

        /* Also try AudioFileOpenURL */
        AudioFileID audioFile = NULL;
        st = AudioFileOpenURL((__bridge CFURLRef)url, kAudioFileReadPermission,
                              0, &audioFile);
        if (st == noErr && audioFile) {
            /* Read properties */
            AudioStreamBasicDescription asbd;
            UInt32 sz = sizeof(asbd);
            AudioFileGetProperty(audioFile, kAudioFilePropertyDataFormat,
                                 &sz, &asbd);

            /* Get audio data length */
            UInt64 dataLen = 0;
            sz = sizeof(dataLen);
            AudioFileGetProperty(audioFile, kAudioFilePropertyAudioDataByteCount,
                                 &sz, &dataLen);

            /* Read a bit of audio data */
            if (dataLen > 0 && dataLen < 65536) {
                void *audioBuf = malloc((size_t)dataLen);
                if (audioBuf) {
                    UInt32 toRead = (UInt32)dataLen;
                    AudioFileReadBytes(audioFile, false, 0, &toRead, audioBuf);
                    free(audioBuf);
                }
            }

            /* Get marker/region info (complex parsing) */
            sz = 0;
            st = AudioFileGetPropertyInfo(audioFile,
                kAudioFilePropertyMarkerList, &sz, NULL);
            if (st == noErr && sz > 0 && sz < 65536) {
                void *markers = malloc(sz);
                if (markers) {
                    AudioFileGetProperty(audioFile,
                        kAudioFilePropertyMarkerList, &sz, markers);
                    free(markers);
                }
            }

            /* Channel layout */
            sz = 0;
            st = AudioFileGetPropertyInfo(audioFile,
                kAudioFilePropertyChannelLayout, &sz, NULL);
            if (st == noErr && sz > 0 && sz < 65536) {
                void *layout = malloc(sz);
                if (layout) {
                    AudioFileGetProperty(audioFile,
                        kAudioFilePropertyChannelLayout, &sz, layout);
                    free(layout);
                }
            }

            AudioFileClose(audioFile);
        }

        unlink(tmppath);
    }
}

/* ================================================================
 * STRATEGY C: In-Memory Parsing (AudioFileOpenWithCallbacks)
 *
 * Uses memory-based callbacks to parse audio data directly
 * from a buffer. This exercises a different code path than
 * file-based or stream-based parsing.
 * ================================================================ */
static void fuzz_memory_parse(const uint8_t *header, size_t hdr_len,
                              AudioFileTypeID fileType,
                              const uint8_t *data, size_t size) {
    size_t total = hdr_len + size;
    uint8_t *buf = malloc(total);
    if (!buf) return;

    memcpy(buf, header, hdr_len);
    memcpy(buf + hdr_len, data, size);

    /* Patch size for FORM/RIFF */
    if (hdr_len >= 12 && (memcmp(header, "FORM", 4) == 0 ||
                          memcmp(header, "RIFF", 4) == 0)) {
        uint32_t bodySize = (uint32_t)(total - 8);
        if (memcmp(header, "RIFF", 4) == 0) {
            buf[4] = bodySize & 0xFF;
            buf[5] = (bodySize >> 8) & 0xFF;
            buf[6] = (bodySize >> 16) & 0xFF;
            buf[7] = (bodySize >> 24) & 0xFF;
        } else {
            buf[4] = (bodySize >> 24) & 0xFF;
            buf[5] = (bodySize >> 16) & 0xFF;
            buf[6] = (bodySize >> 8) & 0xFF;
            buf[7] = bodySize & 0xFF;
        }
    }

    MemFile mf = { buf, total, 0 };

    AudioFileID audioFile = NULL;
    OSStatus st = AudioFileOpenWithCallbacks(
        &mf, mem_read, NULL, mem_getsize, NULL, fileType, &audioFile);

    if (st == noErr && audioFile) {
        /* Read data format */
        AudioStreamBasicDescription asbd;
        UInt32 sz = sizeof(asbd);
        AudioFileGetProperty(audioFile, kAudioFilePropertyDataFormat, &sz, &asbd);

        /* Read packet count */
        UInt64 pktCount = 0;
        sz = sizeof(pktCount);
        AudioFileGetProperty(audioFile, kAudioFilePropertyAudioDataPacketCount,
                             &sz, &pktCount);

        /* Read packets */
        if (pktCount > 0 && pktCount < 1024) {
            UInt32 maxPktSize = 0;
            sz = sizeof(maxPktSize);
            AudioFileGetProperty(audioFile,
                kAudioFilePropertyMaximumPacketSize, &sz, &maxPktSize);

            if (maxPktSize > 0 && maxPktSize < 65536) {
                void *pktBuf = malloc(maxPktSize);
                if (pktBuf) {
                    UInt32 numBytes = maxPktSize;
                    UInt32 numPkts = 1;
                    AudioStreamPacketDescription pd;
                    AudioFileReadPacketData(audioFile, false, &numBytes,
                                           &pd, 0, &numPkts, pktBuf);
                    free(pktBuf);
                }
            }
        }

        /* Magic cookie (codec-specific initialization data) */
        sz = 0;
        st = AudioFileGetPropertyInfo(audioFile,
            kAudioFilePropertyMagicCookieData, &sz, NULL);
        if (st == noErr && sz > 0 && sz < 65536) {
            void *cookie = malloc(sz);
            if (cookie) {
                AudioFileGetProperty(audioFile,
                    kAudioFilePropertyMagicCookieData, &sz, cookie);
                free(cookie);
            }
        }

        AudioFileClose(audioFile);
    }

    free(buf);
}

/* ================================================================
 * LLVMFuzzerTestOneInput — libFuzzer entry point
 *
 * Input structure:
 *   byte 0: format selector (10 formats)
 *   byte 1: strategy selector (stream, file, memory)
 *   byte 2: fragment strategy (for stream parsing)
 *   bytes 3+: fuzz payload
 * ================================================================ */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) return 0;

    uint8_t format    = data[0];
    uint8_t strat     = data[1];
    uint8_t frag_strat = data[2];
    const uint8_t *payload = data + 3;
    size_t psize = size - 3;

    const uint8_t *hdr;
    size_t hdr_len;
    AudioFileTypeID ftype;
    const char *ext;

    switch (format % 10) {
        case 0: /* AIFF */
            hdr = AIFF_MAGIC; hdr_len = sizeof(AIFF_MAGIC);
            ftype = kAudioFileAIFFType; ext = "aiff";
            break;
        case 1: /* AIFC */
            hdr = AIFC_MAGIC; hdr_len = sizeof(AIFC_MAGIC);
            ftype = kAudioFileAIFCType; ext = "aifc";
            break;
        case 2: /* WAV */
            hdr = WAV_MAGIC; hdr_len = sizeof(WAV_MAGIC);
            ftype = kAudioFileWAVEType; ext = "wav";
            break;
        case 3: /* CAF */
            hdr = CAF_MAGIC; hdr_len = sizeof(CAF_MAGIC);
            ftype = kAudioFileCAFType; ext = "caf";
            break;
        case 4: /* MP3 (ID3 header + sync) */
        {
            static const uint8_t mp3_hdr[] = {
                0xFF, 0xFB, 0x90, 0x00  /* MPEG1 Layer3, 128kbps, 44100Hz */
            };
            hdr = mp3_hdr; hdr_len = sizeof(mp3_hdr);
            ftype = kAudioFileMP3Type; ext = "mp3";
            break;
        }
        case 5: /* AAC (ADTS) */
        {
            static const uint8_t aac_hdr[] = {
                0xFF, 0xF1,             /* ADTS sync + ID */
                0x50,                   /* Profile + sample rate + channel */
                0x80, 0x02, 0x00, 0x1C  /* Frame length + buffer fullness */
            };
            hdr = aac_hdr; hdr_len = sizeof(aac_hdr);
            ftype = kAudioFileAAC_ADTSType; ext = "aac";
            break;
        }
        case 6: /* FLAC */
            hdr = FLAC_MAGIC; hdr_len = sizeof(FLAC_MAGIC);
            ftype = kAudioFileFLACType; ext = "flac";
            break;
        case 7: /* AU/SND */
            hdr = AU_MAGIC; hdr_len = sizeof(AU_MAGIC);
            ftype = kAudioFileNextType; ext = "au";
            break;
        case 8: /* AMR */
        {
            static const uint8_t amr_hdr[] = {
                '#', '!', 'A', 'M', 'R', '\n'  /* AMR magic */
            };
            hdr = amr_hdr; hdr_len = sizeof(amr_hdr);
            ftype = kAudioFileAMRType; ext = "amr";
            break;
        }
        case 9: /* MIDI */
            hdr = MIDI_MAGIC; hdr_len = sizeof(MIDI_MAGIC);
            ftype = 0x6D696469; ext = "mid";
            break;
        default:
            return 0;
    }

    switch (strat % 3) {
        case 0: /* Stream parsing */
            fuzz_stream_parse(hdr, hdr_len, ftype, payload, psize, frag_strat);
            break;
        case 1: /* File-based parsing */
            fuzz_file_parse(hdr, hdr_len, payload, psize, ext);
            break;
        case 2: /* Memory-based parsing */
            fuzz_memory_parse(hdr, hdr_len, ftype, payload, psize);
            break;
    }

    return 0;
}
