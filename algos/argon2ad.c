#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include "sysendian.h"
#include "argon2/include/argon2.h"
#include "argon2ad.h"

#define nullptr ((void*)0)
static const char* POW_SECRET = "f412a69fdc6d8ee6663f796b2e7ea53a52b9532a641b2f9cb2a7860108dc4c03";
static const size_t INPUT_BYTES = 80;
static const size_t OUTPUT_BYTES = 32;
static uint8_t* pArgon2Ad = nullptr;
static size_t nArgon2AdLen = 0;
static const int64_t INIT_TIME = 1523321554;

static size_t Argon2FactorN(const int64_t nTime) {
    assert(nTime >= 0);
    static const size_t offset = 9;
    static const int64_t nTimes[] = {
        0,          //                             512KB
        1618876800, // 04/20/2021 @ 12:00am (UTC)  1MB
        1713571200, // 04/20/2024 @ 12:00am (UTC)  2MB
        1808179200  // 04/20/2027 @ 12:00am (UTC)  4MB
    };
    size_t nFactor = 0;
    for (nFactor = 0; nFactor < 3; ++nFactor)
        if (nTime >= nTimes[nFactor] && nTime < nTimes[nFactor+1])
            return nFactor + offset;
    return nFactor + offset;
}

static uint32_t GetArgon2AdSize(const int64_t nTime) {
    const auto factor = Argon2FactorN(nTime);
    return 1024 * (1 << factor);
}

static void UpdateArgon2AdValues() {
    assert (pArgon2Ad != nullptr);
    for (int i = 0; i < nArgon2AdLen; ++i)
        pArgon2Ad[i] = (uint8_t)(i < 256 ? i : i % 256);
}

static void EnsureArgon2MemoryAllocated(const int64_t nTime) {
    const auto nSize = GetArgon2AdSize(nTime);
    if (nSize > nArgon2AdLen) {
        if (nullptr != pArgon2Ad)
            free (pArgon2Ad);
        pArgon2Ad = (uint8_t*) malloc(nSize);
        nArgon2AdLen = nSize;
        UpdateArgon2AdValues();
    }
}

int Argon2Init() {
    EnsureArgon2MemoryAllocated(INIT_TIME);
    return (int)(nArgon2AdLen);
}

void Argon2Deinit() {
    if (nullptr != pArgon2Ad) {
        free(pArgon2Ad);
        pArgon2Ad = nullptr;
    }
}

void Argon2dHash (const char* input, char* output, uint32_t len)
{
    int64_t nTime = (int)time(NULL);

    EnsureArgon2MemoryAllocated (nTime);
    argon2_context ctx;

    ctx.version         = ARGON2_VERSION_13;
    ctx.flags           = ARGON2_DEFAULT_FLAGS;

    ctx.out             = (uint8_t*) output;
    ctx.outlen          = OUTPUT_BYTES;
    ctx.pwd             = (uint8_t*)input;
    ctx.pwdlen          = INPUT_BYTES - 40;
    ctx.salt            = ((uint8_t*) input) + 40;
    ctx.saltlen         = 40;

    ctx.secret          = (uint8_t*) POW_SECRET;
    ctx.secretlen       = strlen (POW_SECRET);
    ctx.ad              = pArgon2Ad;
    ctx.adlen           = GetArgon2AdSize (nTime);

    ctx.m_cost          = 512;
    ctx.t_cost          = 1;
    ctx.lanes           = 2;
    ctx.threads         = 1;

    ctx.allocate_cbk    = nullptr;
    ctx.free_cbk        = nullptr;

    assert (ctx.adlen > 0 && ctx.ad != nullptr);
    const int result = argon2_ctx (&ctx, Argon2_d);
    assert (result == ARGON2_OK);
}
