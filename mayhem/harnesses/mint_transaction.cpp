#include "common.h"
#include "libspark/mint_transaction.h"
#include "streams.h"
#include "version.h"

#include <new>
#include <stdexcept>

// Replaces upstream's src/fuzz/libspark/mint_transaction_fuzz.cpp. That harness built a random
// SpendKey per input and let MintTransaction draw a random nonce per coin (k.randomize()), so each
// input minted fresh random coins and a failure would not replay. This one fuzzes what a node does with
// an untrusted mint: it deserializes the minted coins and the value proof from the input bytes with
// MintTransaction::setMintTransaction and checks them with MintTransaction::verify. Nothing in it is
// random. The input is up to 4 coin streams: the first byte from the end is the stream count (1..4),
// then one 16-bit length per stream but the last (the last stream takes the remaining bytes). The first
// stream is a serialized Coin followed by the SchnorrProof, the others are one serialized Coin each.
// The seeds are real mints written in that layout.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    const size_t count = fdp.ConsumeIntegralInRange<size_t>(1, 4);
    std::vector<uint16_t> lengths;
    for (size_t i = 0; i + 1 < count; i++) {
        lengths.push_back(fdp.ConsumeIntegral<uint16_t>());
    }
    std::vector<CDataStream> streams;
    for (size_t i = 0; i + 1 < count; i++) {
        streams.emplace_back(fdp.ConsumeBytes<unsigned char>(lengths[i]), SER_NETWORK, PROTOCOL_VERSION);
    }
    streams.emplace_back(fdp.ConsumeRemainingBytes<unsigned char>(), SER_NETWORK, PROTOCOL_VERSION);

    spark::MintTransaction mint(spark::Params::get_default());
    try {
        mint.setMintTransaction(streams);
    } catch (const std::bad_alloc&) {
        throw;
    } catch (const std::exception&) {
        return -1;
    }
    for (const CDataStream& stream : streams) {
        if (!stream.empty()) {
            return -1;
        }
    }

    // verify() throws invalid_argument when a coin's value statement is the point at infinity, the
    // documented way Schnorr::verify rejects a bad statement
    try {
        (void)mint.verify();
    } catch (const std::invalid_argument&) {
        return -1;
    }
    return 0;
}
