// Writes the seeds of the spark_spend_parser target: real Spark spend transactions, built the way the node
// builds them (libspark SpendTransaction under the deployed default Params, OP_SPARKSPEND input,
// OP_SPARKSMINT outputs, spend proof in vExtraPayload) and serialized as a CMutableTransaction.
// Not part of the build; compile it like a harness against the sanitizer-free node objects and run
// `gen_spark_spend_seeds <outdir>`. Every proof draws fresh randomness, so rerunning writes different bytes.
#include "key.h"
#include "libspark/spend_transaction.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "spark/state.h"
#include "sparkname.h"
#include "streams.h"
#include "version.h"

#include <cstdio>
#include <fstream>
#include <string>

using namespace spark;
using namespace secp_primitives;

namespace {

struct Input { uint64_t cover_set_id; size_t index; };

std::vector<unsigned char> serial_context(uint8_t tag)
{
    return std::vector<unsigned char>(32, tag);
}

// inputs.size() coins spent from their own cover sets, `outputs` fresh output coins, `transparent` zatoshi
// paid to a transparent output. extension != nullptr appends a Spark name payload (V2 only).
CTransaction build(
    SpendTransactionVersion version,
    const std::vector<uint64_t>& cover_set_ids,
    size_t outputs,
    uint64_t transparent,
    CSparkNameTxData* extension)
{
    const spark::Params* params = spark::Params::get_default();
    SpendKey spend_key(params);
    FullViewKey full_view_key(spend_key);
    IncomingViewKey incoming_view_key(full_view_key);
    Address address(incoming_view_key, 12345);

    CMutableTransaction tx;
    CScript spend_script;
    spend_script << OP_SPARKSPEND;
    tx.vin.emplace_back(COutPoint(), spend_script, std::numeric_limits<uint32_t>::max());
    tx.nVersion = 3;
    tx.nType = version == SpendTransactionVersion::V2 ? TRANSACTION_SPARK_V2 : TRANSACTION_SPARK;
    CScript pay_to;
    pay_to << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0x42) << OP_EQUALVERIFY << OP_CHECKSIG;
    tx.vout.emplace_back(transparent, pay_to);
    const uint256 metadata_hash = tx.GetHash();

    std::vector<InputCoinData> inputs;
    std::unordered_map<uint64_t, CoverSetData> cover_set_data;
    std::unordered_map<uint64_t, std::vector<Coin>> cover_sets;
    std::map<uint64_t, uint256> block_hashes;
    uint64_t total_in = 0;
    for (size_t u = 0; u < cover_set_ids.size(); u++) {
        const uint64_t id = cover_set_ids[u];
        std::vector<Coin> set;
        const size_t spent_index = 1 + u;
        for (size_t i = 0; i < 6; i++) {
            Scalar k;
            k.randomize();
            set.emplace_back(params, COIN_TYPE_MINT, k, address, 1000 + 7 * i + 100 * u, "memo",
                             serial_context(uint8_t(10 * u + i)));
        }
        IdentifiedCoinData identified = set[spent_index].identify(incoming_view_key);
        RecoveredCoinData recovered = set[spent_index].recover(full_view_key, identified);

        InputCoinData input;
        input.cover_set_id = id;
        input.index = spent_index;
        input.k = identified.k;
        input.s = recovered.s;
        input.T = recovered.T;
        input.v = identified.v;
        inputs.push_back(input);
        total_in += identified.v;

        CoverSetData data;
        data.cover_set_size = set.size();
        data.cover_set_representation = serial_context(uint8_t(0xA0 + id));
        data.cover_set_representation.insert(
            data.cover_set_representation.end(), metadata_hash.begin(), metadata_hash.end());
        cover_set_data[id] = data;
        cover_sets[id] = set;
        uint256 h;
        h.SetHex(std::string(63, '0') + char('1' + (id % 9)));
        block_hashes[id] = h;
    }

    std::vector<OutputCoinData> out_data;
    uint64_t total_out = transparent;
    for (size_t j = 0; j < outputs; j++) {
        OutputCoinData o;
        o.address = address;
        o.v = 100 + 13 * j;
        o.memo = j == 0 ? "change" : "";
        total_out += o.v;
        out_data.push_back(o);
    }
    const uint64_t fee = total_in - total_out;

    uint256 commitment;
    if (extension) {
        commitment = CSparkNameManager::GetSparkNameCommitment(*extension);
    }
    SpendTransaction spend(
        params, full_view_key, spend_key, inputs, cover_set_data, cover_sets, fee, transparent, out_data,
        version, commitment, version == SpendTransactionVersion::V2 ? block_hashes : std::map<uint64_t, uint256>());

    CDataStream payload(SER_NETWORK, PROTOCOL_VERSION);
    payload << spend;
    if (extension) {
        payload << *extension;
    }
    tx.vExtraPayload.assign(payload.begin(), payload.end());
    for (const auto& coin : spend.getOutCoins()) {
        CDataStream encoded(SER_NETWORK, PROTOCOL_VERSION);
        encoded << coin;
        CScript mint;
        mint << OP_SPARKSMINT;
        mint.insert(mint.end(), encoded.begin(), encoded.end());
        tx.vout.emplace_back(0, mint);
    }
    return CTransaction(tx);
}

void write(const std::string& dir, const char* name, const CTransaction& tx)
{
    CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
    s << tx;
    std::ofstream f(dir + "/" + name, std::ios::binary);
    f.write(s.data(), s.size());
}

}

int main(int argc, char** argv)
{
    if (argc != 2) {
        return 1;
    }
    ECCVerifyHandle verify_handle;
    const std::string dir = argv[1];
    const auto V1 = SpendTransactionVersion::V1;
    const auto V2 = SpendTransactionVersion::V2;
    write(dir, "v1_one_input.bin", build(V1, {1}, 1, 0, nullptr));
    write(dir, "v1_two_inputs_transparent_out.bin", build(V1, {1, 2}, 2, 50, nullptr));
    write(dir, "v2_one_input.bin", build(V2, {1}, 1, 0, nullptr));
    write(dir, "v2_two_inputs_transparent_out.bin", build(V2, {3, 4}, 2, 50, nullptr));

    CSparkNameTxData name;
    name.name = "fuzzname";
    name.sparkAddress = "sr1" + std::string(40, 'q');
    name.addressOwnershipProof.assign(64, 0x5a);
    name.sparkNameValidityBlocks = 1000;
    name.additionalInfo = "https://example.org";
    write(dir, "v2_spark_name_extension.bin", build(V2, {1}, 1, 0, &name));
    return 0;
}
