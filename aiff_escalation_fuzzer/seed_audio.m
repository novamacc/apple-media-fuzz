/*
 * seed_audio.m — Generate audio format seed corpus for all 10 formats
 *
 * Build:  clang -framework Foundation -framework AudioToolbox -o seed_audio seed_audio.m
 * Run:    ./seed_audio corpus/
 */
#import <Foundation/Foundation.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static void write_seed(const char *dir, const char *name,
                       const void *data, size_t len) {
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "wb");
    if (f) { fwrite(data, 1, len, f); fclose(f); }
    printf("  [+] %-40s (%5zu bytes)\n", name, len);
}

/* Build a minimal valid AIFF file with COMM + SSND chunks */
static void gen_aiff(const char *dir, const char *name, int isAIFC) {
    uint8_t buf[128];
    memset(buf, 0, sizeof(buf));
    memcpy(buf, "FORM", 4);
    memcpy(buf+8, isAIFC ? "AIFC" : "AIFF", 4);
    /* COMM chunk: 2ch, 100 frames, 16-bit, 44100Hz */
    memcpy(buf+12, "COMM", 4);
    uint32_t commSize = isAIFC ? 24 : 18;
    buf[15] = commSize;
    buf[18] = 0; buf[19] = 2;       /* numChannels=2 */
    buf[23] = 100;                    /* numFrames=100 */
    buf[26] = 0; buf[27] = 16;      /* sampleSize=16 */
    /* 44100 Hz as 80-bit IEEE 754 extended */
    buf[28]=0x40; buf[29]=0x0D; buf[30]=0xAC; buf[31]=0x44;
    if (isAIFC) {
        memcpy(buf+38, "NONE", 4); /* compression type */
    }
    /* SSND chunk */
    size_t ssndOff = 12 + 8 + commSize;
    memcpy(buf+ssndOff, "SSND", 4);
    buf[ssndOff+7] = 16; /* chunk size */
    /* offset + blockSize = 0 */
    /* audio data follows */
    size_t total = ssndOff + 8 + 16;
    uint32_t formSize = (uint32_t)(total - 8);
    buf[4] = (formSize>>24)&0xFF; buf[5] = (formSize>>16)&0xFF;
    buf[6] = (formSize>>8)&0xFF;  buf[7] = formSize&0xFF;
    write_seed(dir, name, buf, total);
}

static void gen_wav(const char *dir) {
    uint8_t buf[80];
    memset(buf, 0, sizeof(buf));
    memcpy(buf, "RIFF", 4);
    memcpy(buf+8, "WAVE", 4);
    /* fmt chunk */
    memcpy(buf+12, "fmt ", 4);
    buf[16]=16; /* chunk size (LE) */
    buf[20]=1;  /* PCM */
    buf[22]=2;  /* stereo */
    buf[24]=0x44; buf[25]=0xAC; /* 44100 Hz (LE) */
    buf[28]=0x10; buf[29]=0xB1; buf[30]=0x02; /* byte rate */
    buf[32]=4;  /* block align */
    buf[34]=16; /* bits/sample */
    /* data chunk */
    memcpy(buf+36, "data", 4);
    buf[40]=16;
    size_t total = 56;
    uint32_t riffSize = (uint32_t)(total - 8);
    buf[4]=riffSize&0xFF; buf[5]=(riffSize>>8)&0xFF;
    write_seed(dir, "wav_pcm16.bin", buf, total);
}

static void gen_caf(const char *dir) {
    uint8_t buf[64];
    memset(buf, 0, sizeof(buf));
    memcpy(buf, "caff", 4);
    buf[5]=1; /* version 1 */
    /* desc chunk */
    memcpy(buf+8, "desc", 4);
    buf[15]=32; /* chunk size */
    /* sample rate 44100 as float64 */
    uint64_t sr = 0x40D5888000000000ULL; /* 44100.0 */
    for (int i=0; i<8; i++) buf[24+i] = (sr >> (56-i*8))&0xFF;
    memcpy(buf+32, "lpcm", 4); /* format ID */
    buf[39]=4; /* format flags */
    buf[43]=4; /* bytes per packet */
    buf[47]=1; /* frames per packet */
    buf[51]=2; /* channels */
    buf[55]=16; /* bits per channel */
    write_seed(dir, "caf_lpcm.bin", buf, 56);
}

static void gen_au(const char *dir) {
    uint8_t buf[40];
    memset(buf, 0, sizeof(buf));
    memcpy(buf, ".snd", 4);
    buf[7]=24;    /* data offset */
    buf[11]=16;   /* data size */
    buf[14]=0; buf[15]=3; /* encoding: 16-bit linear PCM */
    buf[16]=0; buf[17]=0; buf[18]=0xAC; buf[19]=0x44; /* 44100 Hz */
    buf[23]=2; /* channels */
    write_seed(dir, "au_pcm.bin", buf, 40);
}

static void gen_mp3(const char *dir) {
    uint8_t buf[32];
    memset(buf, 0, sizeof(buf));
    /* MPEG1 Layer3 frame header */
    buf[0]=0xFF; buf[1]=0xFB; /* sync + MPEG1, Layer3 */
    buf[2]=0x90; /* 128kbps, 44100Hz */
    buf[3]=0x64; /* Joint stereo, padding */
    write_seed(dir, "mp3_frame.bin", buf, 32);
}

static void gen_aac(const char *dir) {
    uint8_t buf[32];
    memset(buf, 0, sizeof(buf));
    /* ADTS header */
    buf[0]=0xFF; buf[1]=0xF1; /* syncword + MPEG4 AAC */
    buf[2]=0x50; /* AAC-LC, 44100Hz */
    buf[3]=0x80; buf[4]=0x02; buf[5]=0x00; buf[6]=0x1C;
    write_seed(dir, "aac_adts.bin", buf, 32);
}

static void gen_flac(const char *dir) {
    uint8_t buf[48];
    memset(buf, 0, sizeof(buf));
    memcpy(buf, "fLaC", 4);
    /* STREAMINFO block (type=0, last=1) */
    buf[4] = 0x80; /* last + type 0 */
    buf[7] = 34;   /* block size */
    /* min/max block size */
    buf[8]=0x10; buf[9]=0x00; buf[10]=0x10; buf[11]=0x00; /* 4096 */
    /* min/max frame size = 0 */
    /* sample rate (44100), channels (2), bps (16) */
    buf[18]=0x0A; buf[19]=0xC4; buf[20]=0x42; buf[21]=0xF0;
    write_seed(dir, "flac_stream.bin", buf, 42);
}

static void gen_amr(const char *dir) {
    uint8_t buf[16];
    memcpy(buf, "#!AMR\n", 6);
    buf[6] = 0x3C; /* frame type 7, quality */
    memset(buf+7, 0xAA, 9);
    write_seed(dir, "amr_frame.bin", buf, 16);
}

static void gen_midi(const char *dir) {
    uint8_t buf[32];
    memset(buf, 0, sizeof(buf));
    memcpy(buf, "MThd", 4);
    buf[7]=6;     /* header size */
    buf[11]=1;    /* format 1 */
    buf[13]=1;    /* 1 track */
    buf[14]=0; buf[15]=96; /* ticks per quarter */
    /* Track chunk */
    memcpy(buf+14, "MTrk", 4);
    buf[21]=4; /* track size */
    buf[22]=0x00; buf[23]=0xFF; buf[24]=0x2F; buf[25]=0x00; /* End of track */
    write_seed(dir, "midi_minimal.bin", buf, 26);
}

int main(int argc, char *argv[]) {
    const char *dir = argc > 1 ? argv[1] : "corpus";
    mkdir(dir, 0755);
    printf("[*] Generating audio seed corpus in %s/\n\n", dir);

    gen_aiff(dir, "aiff_stereo.bin", 0);
    gen_aiff(dir, "aifc_stereo.bin", 1);
    gen_wav(dir);
    gen_caf(dir);
    gen_au(dir);
    gen_mp3(dir);
    gen_aac(dir);
    gen_flac(dir);
    gen_amr(dir);
    gen_midi(dir);

    printf("\n[+] 10 audio format seeds generated.\n");
    return 0;
}
