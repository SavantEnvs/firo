// Deterministic group elements for the fixed statements the verifier harnesses check proofs against.
#pragma once

#include "secp256k1/include/GroupElement.h"

#include <cstdint>

using namespace secp_primitives;

inline GroupElement fixed_gen(uint8_t domain, uint8_t tag)
{
    unsigned char seed[32] = {0};
    seed[0] = tag;
    seed[30] = domain;
    seed[31] = 0x5a;
    GroupElement g;
    g.generate(seed);
    return g;
}
