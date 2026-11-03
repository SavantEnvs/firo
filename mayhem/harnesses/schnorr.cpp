#include "common.h"
#include "libspark/schnorr.h"
#include "libspark/schnorr_proof.h"
#include "streams.h"
#include "version.h"

#include <cassert>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* buf, size_t len)
{
    FuzzedDataProvider fdp(buf, len);

    GroupElement G0 = fz_group_element(fdp);
    Scalar y0 = fz_scalar(fdp);
    GroupElement Y0 = G0 * y0;

    spark::Schnorr schnorr0(G0);
    spark::SchnorrProof proof0;
    schnorr0.prove(y0, Y0, proof0);

    CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
    serialized << proof0;
    spark::SchnorrProof deserialized;
    serialized >> deserialized;
    assert(proof0.A == deserialized.A);
    assert(proof0.t == deserialized.t);
    assert(schnorr0.verify(Y0, proof0));

    const size_t n = fdp.ConsumeIntegralInRange<size_t>(1, 8);
    GroupElement G1 = fz_group_element(fdp);
    std::vector<Scalar> y1 = fz_scalars(fdp, n);
    std::vector<GroupElement> Y1;
    for (size_t i = 0; i < n; i++) {
        Y1.emplace_back(G1 * y1[i]);
    }

    spark::Schnorr schnorr1(G1);
    spark::SchnorrProof proof1;
    schnorr1.prove(y1, Y1, proof1);
    assert(schnorr1.verify(Y1, proof1));

    // Negative probes come from the input too, nudged so they differ from the real values (a probe equal
    // to the real value would verify). prove() draws its nonce internally, but no assert below depends on it.
    GroupElement evil_Y = fz_group_element(fdp);
    if (evil_Y == Y1[0]) {
        evil_Y += G1;
    }
    assert(!schnorr1.verify(evil_Y, proof1));

    spark::SchnorrProof evil_proof = proof1;
    evil_proof.A = fz_group_element(fdp);
    if (evil_proof.A == proof1.A) {
        evil_proof.A += G1;
    }
    assert(!schnorr1.verify(Y1, evil_proof));

    evil_proof = proof1;
    evil_proof.t = fz_scalar(fdp);
    if (evil_proof.t == proof1.t) {
        evil_proof.t += Scalar(uint64_t(1));
    }
    assert(!schnorr1.verify(Y1, evil_proof));
    return 0;
}
