#ifndef MERIT_H
#define MERIT_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>

#define MERIT_PROOF_SIZE 42

void merit_hash(const char *input, char *output, uint32_t length);

#ifdef __cplusplus
}
#endif

#endif // MERIT_H
