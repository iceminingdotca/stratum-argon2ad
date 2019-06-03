#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "../sha3/sph_blake.h"
#include "../sha3/sph_bmw.h"
#include "../sha3/sph_keccak.h"

void lbk3_hash(const char* input, char* output, uint32_t len)
{
    sph_bmw256_context       ctx_bmw;
    sph_blake256_context     ctx_blake;
    sph_keccak256_context    ctx_keccak;

    //these uint512 in the c++ source of the client are backed by an array of uint32
    // todo: this is all really 256, so don't waste space.. trim to 256 at the end for now
    uint32_t hashA[16], hashB[16], hashC[16];;	

    sph_bmw256_init(&ctx_bmw);
    sph_bmw256 (&ctx_bmw, input, 64);
    sph_bmw256_close(&ctx_bmw, hashA);

    sph_blake256_init(&ctx_blake);
    sph_blake256 (&ctx_blake, hashA, 64);
    sph_blake256_close(&ctx_blake, hashB);

    sph_keccak256_init(&ctx_keccak);
    sph_keccak256 (&ctx_keccak, hashB, 64);
    sph_keccak256_close(&ctx_keccak, hashC);

    memcpy(output, hashC, 32);
}

