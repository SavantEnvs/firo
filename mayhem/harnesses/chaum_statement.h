// Fixed Chaum statements shared by the chaum harness and the tool that wrote its seeds.
// Everything is derived from constants, so the same input always verifies against the same statement.
#pragma once

#include "fixed_gen.h"
#include "libspark/chaum.h"
#include "libspark/chaum_proof.h"

#include <array>
#include <vector>

using namespace secp_primitives;

namespace chaum_stmt {

constexpr size_t MAX_N = 4;  // most inputs a statement proves

struct Statement {
    GroupElement F, G, H, U;
    Scalar mu;
    // x/y/z are the witnesses; the statement that proves n inputs is the first n entries of S and T
    std::array<Scalar, MAX_N> x, y, z;
    std::array<GroupElement, MAX_N> S, T;
};

inline Statement build()
{
    Statement s;
    s.F = fixed_gen(1, 0);
    s.G = fixed_gen(1, 1);
    s.H = fixed_gen(1, 2);
    s.U = fixed_gen(1, 3);
    s.mu = Scalar(uint64_t(7));
    for (size_t i = 0; i < MAX_N; i++) {
        s.x[i] = Scalar(uint64_t(13 + 17 * i));
        s.y[i] = Scalar(uint64_t(101 + 3 * i));
        s.z[i] = Scalar(uint64_t(1000 + 7 * i));
        s.S[i] = s.F * s.x[i] + s.G * s.y[i] + s.H * s.z[i];
        s.T[i] = (s.U + s.G * s.y[i].negate()) * s.x[i].inverse();
    }
    return s;
}

}
