// Fixed BP+ range-proof statements shared by the bpplus harness and the tool that wrote its seeds.
// Everything here is derived deterministically from constants, so the same input always verifies
// against the same statement.
#pragma once

#include "libspark/bpplus.h"
#include "libspark/bpplus_proof.h"

#include <array>
#include <cstdint>
#include <vector>

using namespace secp_primitives;

namespace bpplus_stmt {

constexpr size_t N = 8;      // bit length of each range proof
constexpr size_t MAX_M = 4;  // largest (padded) number of aggregated values
constexpr size_t MAX_UNPADDED_M = 4;

inline GroupElement gen(uint8_t tag)
{
    unsigned char seed[32] = {0};
    seed[0] = tag;
    seed[31] = 0x5a;
    GroupElement g;
    g.generate(seed);
    return g;
}

struct Statement {
    GroupElement G, H;
    std::vector<GroupElement> Gi, Hi;
    // C[m-1] is the commitment list of the statement that aggregates m values
    std::array<std::vector<GroupElement>, MAX_UNPADDED_M> C;
    std::array<std::vector<Scalar>, MAX_UNPADDED_M> v, r;
};

inline Statement build()
{
    Statement s;
    s.G = gen(0);
    s.H = gen(1);
    for (size_t i = 0; i < N * MAX_M; i++) {
        s.Gi.push_back(gen(static_cast<uint8_t>(2 + i)));
        s.Hi.push_back(gen(static_cast<uint8_t>(100 + i)));
    }
    for (size_t m = 1; m <= MAX_UNPADDED_M; m++) {
        for (size_t j = 0; j < m; j++) {
            Scalar v(static_cast<uint64_t>(37 * j + 11));
            Scalar r(static_cast<uint64_t>(1000 + 7 * j + m));
            s.v[m - 1].push_back(v);
            s.r[m - 1].push_back(r);
            s.C[m - 1].push_back(s.G * v + s.H * r);
        }
    }
    return s;
}

}
