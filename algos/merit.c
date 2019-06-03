#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sha3/sph_sha2.h>

void merit_hash(const char *input, char *output, uint32_t length)
{
    sph_sha256_context ctx_sha256;
    uint32_t hash[8];

    sph_sha256_init(&ctx_sha256);
    sph_sha256(&ctx_sha256, input, length);
    sph_sha256_close(&ctx_sha256, hash);

    sph_sha256_init(&ctx_sha256);
    sph_sha256(&ctx_sha256, &hash[0], 32);
    sph_sha256_close(&ctx_sha256, hash);

    memcpy(output, hash, 32);
}
