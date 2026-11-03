#include "bpplus_statement.h"
#include "common.h"
#include "streams.h"
#include "version.h"

#include <new>

// Replaces upstream's src/fuzz/libspark/bpplus_fuzz.cpp. That harness overwrote its fuzzed sizes with
// constants, drew every generator and scalar from randomize()/rand(), and so re-proved a fresh random
// statement each run: no input replayed. This one fuzzes the surface a verifier exposes: an untrusted
// BPPlusProof deserialized from the input bytes and checked with BPPlus::verify against a fixed,
// deterministic statement (small N=8, up to 4 aggregated values). The first input byte from the end
// picks how many values the statement aggregates (1..4); the rest is the serialized proof. The seeds
// are valid proofs for each statement, so mutations reach the verification arithmetic.
static const bpplus_stmt::Statement* g_stmt;

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
    static const bpplus_stmt::Statement stmt = bpplus_stmt::build();
    g_stmt = &stmt;
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    const size_t m = fdp.ConsumeIntegralInRange<size_t>(1, bpplus_stmt::MAX_UNPADDED_M);
    std::vector<unsigned char> bytes = fdp.ConsumeRemainingBytes<unsigned char>();

    CDataStream stream(bytes, SER_NETWORK, PROTOCOL_VERSION);
    spark::BPPlusProof proof;
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

    spark::BPPlus bpplus(g_stmt->G, g_stmt->H, g_stmt->Gi, g_stmt->Hi, bpplus_stmt::N);
    (void)bpplus.verify(g_stmt->C[m - 1], proof);
    return 0;
}
