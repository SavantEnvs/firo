// Fixed Grootle statement shared by the grootle harness and the tool that wrote its seeds.
// Everything is derived from constants, so the same input always verifies against the same statement.
#pragma once

#include "fixed_gen.h"
#include "libspark/grootle.h"
#include "libspark/grootle_proof.h"

#include <vector>

using namespace secp_primitives;

namespace grootle_stmt {

constexpr size_t n = 2, m = 3;
constexpr size_t N = 8;            // n^m: the commitment set size
constexpr size_t L = 5;            // index of the proven commitment
constexpr size_t MAX_SHRINK = 2;   // the cover set may be the last N, N-1 or N-2 commitments

struct Statement {
    GroupElement H;
    std::vector<GroupElement> Gi, Hi;
    std::vector<GroupElement> S, V;  // the commitment sets, with the offsets already added at L
    GroupElement S1, V1;             // the offsets: S[L] == S1 + H*s, V[L] == V1 + H*v
    Scalar s, v;
    std::vector<unsigned char> root;
};

inline Statement build()
{
    Statement st;
    st.H = fixed_gen(2, 0);
    for (size_t i = 0; i < n * m; i++) {
        st.Gi.push_back(fixed_gen(2, static_cast<uint8_t>(1 + i)));
        st.Hi.push_back(fixed_gen(2, static_cast<uint8_t>(50 + i)));
    }
    for (size_t i = 0; i < N; i++) {
        st.S.push_back(fixed_gen(2, static_cast<uint8_t>(100 + i)));
        st.V.push_back(fixed_gen(2, static_cast<uint8_t>(150 + i)));
    }
    st.s = Scalar(uint64_t(77));
    st.v = Scalar(uint64_t(91));
    st.S1 = st.S[L];
    st.V1 = st.V[L];
    st.S[L] += st.H * st.s;
    st.V[L] += st.H * st.v;
    st.root.resize(32);
    Scalar(uint64_t(5)).serialize(st.root.data());
    return st;
}

}
