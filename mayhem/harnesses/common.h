// Shared helpers for the ported libspark harnesses. The upstream FuzzedSecp256k1Object builds
// group elements/scalars from dangling temporaries and zero values, which aborts every input.
#pragma once

#include "fuzz/FuzzedDataProvider.h"
#include "secp256k1/include/GroupElement.h"
#include "secp256k1/include/Scalar.h"

#include <cstdint>
#include <vector>

using namespace secp_primitives;

inline Scalar fz_scalar(FuzzedDataProvider& fdp)
{
    std::vector<unsigned char> b = fdp.ConsumeBytes<unsigned char>(32);
    b.resize(32);
    Scalar s(b.data());
    if (s.isZero()) {
        s = Scalar(uint64_t(1));
    }
    return s;
}

inline std::vector<Scalar> fz_scalars(FuzzedDataProvider& fdp, size_t n)
{
    std::vector<Scalar> out;
    out.reserve(n);
    for (size_t i = 0; i < n; i++) {
        out.emplace_back(fz_scalar(fdp));
    }
    return out;
}

inline GroupElement fz_group_element(FuzzedDataProvider& fdp)
{
    std::vector<unsigned char> seed = fdp.ConsumeBytes<unsigned char>(32);
    seed.resize(32);
    GroupElement g;
    g.generate(seed.data());
    return g;
}
