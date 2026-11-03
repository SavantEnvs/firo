#include "libspark/spend_transaction.h"
#include "streams.h"
#include "version.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <vector>

// Ported from src/fuzz/libspark/spend_transaction_v2_payload_fuzz.cpp: exercises the bounded inner V2
// wire parser and reserializer. The upstream oracle demanded serialize(parse(x)) == x, but
// GroupElement::deserialize takes the oddness and infinity flag bytes as any value and
// re-serialization normalises them to 0/1, so a lenient (non-canonical) encoding is accepted by
// design. The oracle here is idempotence: the canonical form must re-parse, and re-serializing that
// parse must give the same bytes.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size == 0) {
        return 0;
    }

    const std::size_t expected_outputs =
        1 + (data[0] % spark::MAX_SPARK_V2_OUTPUTS);
    CDataStream stream(
        std::vector<unsigned char>(data + 1, data + size),
        SER_NETWORK,
        PROTOCOL_VERSION);
    spark::SpendTransaction transaction(
        spark::Params::get_default(),
        spark::SpendTransactionVersion::V2,
        expected_outputs);
    try {
        stream >> transaction;
    } catch (const std::bad_alloc&) {
        throw;
    } catch (const std::exception&) {
        return 0;
    }
    if (!stream.empty()) {
        return 0;
    }

    CDataStream canonical(SER_NETWORK, PROTOCOL_VERSION);
    canonical << transaction;

    // The library's own output must parse; an exception from here is a library defect and is left
    // to propagate with its library frames.
    CDataStream reparse_stream(
        std::vector<unsigned char>(canonical.begin(), canonical.end()),
        SER_NETWORK,
        PROTOCOL_VERSION);
    spark::SpendTransaction reparsed(
        spark::Params::get_default(),
        spark::SpendTransactionVersion::V2,
        expected_outputs);
    reparse_stream >> reparsed;

    CDataStream again(SER_NETWORK, PROTOCOL_VERSION);
    again << reparsed;
    if (!reparse_stream.empty() || again.size() != canonical.size() ||
        !std::equal(canonical.begin(), canonical.end(), again.begin())) {
        std::abort();
    }
    return 0;
}
