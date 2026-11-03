#include "common.h"
#include "grootle_statement.h"
#include "streams.h"
#include "version.h"

#include <new>

// Replaces upstream's src/fuzz/libspark/grootle_fuzz.cpp. That harness drew H, Gi, Hi, S and V from
// randomize() and proved a fresh statement on every input, so nothing replayed. This one fuzzes what a
// verifier exposes: a GrootleProof deserialized from the input bytes and checked with Grootle::verify
// against a fixed, deterministic statement (n=2, m=3, 8 commitments). The last input byte picks the
// cover set size (8, 7 or 6); the rest is the serialized proof. The seeds are valid proofs, one per
// cover set size.
static const grootle_stmt::Statement* g_stmt;

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
    static const grootle_stmt::Statement stmt = grootle_stmt::build();
    g_stmt = &stmt;
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    const size_t shrink = fdp.ConsumeIntegralInRange<size_t>(0, grootle_stmt::MAX_SHRINK);
    std::vector<unsigned char> bytes = fdp.ConsumeRemainingBytes<unsigned char>();

    CDataStream stream(bytes, SER_NETWORK, PROTOCOL_VERSION);
    spark::GrootleProof proof;
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

    spark::Grootle grootle(g_stmt->H, g_stmt->Gi, g_stmt->Hi, grootle_stmt::n, grootle_stmt::m);
    (void)grootle.verify(g_stmt->S, g_stmt->S1, g_stmt->V, g_stmt->V1, g_stmt->root,
                         grootle_stmt::N - shrink, proof);
    return 0;
}
