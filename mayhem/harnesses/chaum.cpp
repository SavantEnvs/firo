#include "chaum_statement.h"
#include "common.h"
#include "streams.h"
#include "version.h"

#include <new>

// Replaces upstream's src/fuzz/libspark/chaum_fuzz.cpp. That harness drew F, G, H, U from randomize()
// and proved a fresh statement on every input, so nothing replayed. This one fuzzes what a verifier
// exposes: a ChaumProofV1 deserialized from the input bytes and checked with Chaum::verify_v1 against a
// fixed, deterministic statement (1..4 inputs). The last input byte picks how many inputs the
// statement has; the rest is the serialized proof. The seeds are valid proofs, one per input count.
static const chaum_stmt::Statement* g_stmt;

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
    static const chaum_stmt::Statement stmt = chaum_stmt::build();
    g_stmt = &stmt;
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    const size_t n = fdp.ConsumeIntegralInRange<size_t>(1, chaum_stmt::MAX_N);
    std::vector<unsigned char> bytes = fdp.ConsumeRemainingBytes<unsigned char>();

    CDataStream stream(bytes, SER_NETWORK, PROTOCOL_VERSION);
    spark::ChaumProofV1 proof;
    try {
        stream >> proof;
    } catch (const std::bad_alloc&) {
        throw;
    } catch (const std::exception&) {
        return -1;
    }
    if (!stream.empty()) {
        return -1;
    }
    // verify_v1 throws on a proof whose vectors do not have one entry per statement input
    if (proof.A2.size() != n || proof.t1.size() != n) {
        return -1;
    }

    const std::vector<GroupElement> S(g_stmt->S.begin(), g_stmt->S.begin() + n);
    const std::vector<GroupElement> T(g_stmt->T.begin(), g_stmt->T.begin() + n);
    spark::Chaum chaum(g_stmt->F, g_stmt->G, g_stmt->H, g_stmt->U);
    (void)chaum.verify_v1(g_stmt->mu, S, T, proof);
    return 0;
}
