#include "coin_statement.h"
#include "common.h"
#include "streams.h"
#include "version.h"

#include <cassert>
#include <new>

// Replaces upstream's src/fuzz/libspark/coin_fuzz.cpp. That harness built a random SpendKey and a random
// serial context per input, so a failure would not replay. Nothing here is random; the last input bit
// picks one of two modes:
//  - parse (odd last byte): the rest of the input is a serialized spark::Coin, as a node receives one
//    from a mint or spend transaction. It is deserialized with CDataStream and identified against a
//    fixed IncomingViewKey and serial context; an identified coin is recovered with the fixed
//    FullViewKey. The seeds are real mint and spend coins for that key.
//  - round trip (even last byte): a coin of either type is built from input-derived index, value, memo,
//    nonce and serial context for an address of the fixed key, serialized, deserialized, identified and
//    recovered, and every recovered field is asserted equal to what went in.
static const coin_stmt::Keys* g_keys;

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
    static const coin_stmt::Keys keys(spark::Params::get_default());
    g_keys = &keys;
    return 0;
}

static void check_recovered(spark::Coin& coin, const spark::IdentifiedCoinData& i_data)
{
    const spark::Params* params = spark::Params::get_default();
    spark::RecoveredCoinData r_data = coin.recover(g_keys->full_view_key, i_data);
    assert(r_data.T * r_data.s + g_keys->full_view_key.get_D() == params->get_U());
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* buf, size_t len)
{
    FuzzedDataProvider fdp(buf, len);
    const spark::Params* params = spark::Params::get_default();

    if (fdp.ConsumeBool()) {
        std::vector<unsigned char> bytes = fdp.ConsumeRemainingBytes<unsigned char>();
        CDataStream stream(bytes, SER_NETWORK, PROTOCOL_VERSION);
        spark::Coin coin;
        try {
            stream >> coin;
        } catch (const std::bad_alloc&) {
            throw;
        } catch (const std::exception&) {
            return -1;
        }
        if (!stream.empty()) {
            return -1;
        }
        coin.setSerialContext(g_keys->serial_context);

        // identify throws runtime_error for a coin that is not ours (bad tag, malformed, bad memo
        // encoding) and invalid_argument for an encrypted diversifier of the wrong size
        spark::IdentifiedCoinData i_data;
        try {
            i_data = coin.identify(g_keys->incoming_view_key);
        } catch (const std::bad_alloc&) {
            throw;
        } catch (const std::runtime_error&) {
            return -1;
        } catch (const std::invalid_argument&) {
            return -1;
        }
        check_recovered(coin, i_data);
        return 0;
    }

    const char type = fdp.ConsumeBool() ? spark::COIN_TYPE_MINT : spark::COIN_TYPE_SPEND;
    const uint64_t index = fdp.ConsumeIntegral<uint16_t>();
    const uint64_t value = fdp.ConsumeIntegral<uint64_t>();
    const std::string memo = fdp.ConsumeRandomLengthString(params->get_memo_bytes());
    const Scalar k = fz_scalar(fdp);
    const std::vector<unsigned char> serial_context =
        fdp.ConsumeBytes<unsigned char>(fdp.ConsumeIntegralInRange<size_t>(0, 64));

    spark::Address address(g_keys->incoming_view_key, index);
    spark::Coin built(params, type, k, address, value, memo, serial_context);

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << built;
    spark::Coin coin;
    stream >> coin;
    assert(stream.empty());
    assert(coin == built);
    coin.setSerialContext(serial_context);

    spark::IdentifiedCoinData i_data = coin.identify(g_keys->incoming_view_key);
    assert(i_data.i == index);
    assert(i_data.d == address.get_d());
    assert(i_data.v == value);
    assert(i_data.k == k);
    assert(i_data.memo == memo);
    check_recovered(coin, i_data);
    return 0;
}
