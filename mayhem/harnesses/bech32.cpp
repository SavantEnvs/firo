#include "fuzz/FuzzedDataProvider.h"
#include "libspark/bech32.h"

#include <cassert>
#include <string>
#include <vector>

static bool case_insensitive_equal(const std::string& a, const std::string& b)
{
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        char x = a[i], y = b[i];
        if (x >= 'A' && x <= 'Z') x -= ('A' - 'a');
        if (y >= 'A' && y <= 'Z') y -= ('A' - 'a');
        if (x != y) return false;
    }
    return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* buf, size_t len)
{
    FuzzedDataProvider fdp(buf, len);

    std::string text = fdp.ConsumeRandomLengthString(len / 2);
    const auto r1 = bech32::decode(text);
    if (r1.hrp.empty()) {
        assert(r1.encoding == bech32::Encoding::INVALID);
        assert(r1.data.empty());
    } else {
        assert(r1.encoding != bech32::Encoding::INVALID);
        const std::string reencoded = bech32::encode(r1.hrp, r1.data, r1.encoding);
        assert(case_insensitive_equal(text, reencoded));
    }

    const int frombits = fdp.ConsumeIntegralInRange<int>(1, 8);
    const int tobits = fdp.ConsumeIntegralInRange<int>(1, 8);
    const bool pad = fdp.ConsumeBool();
    std::vector<uint8_t> input = fdp.ConsumeBytes<uint8_t>(fdp.remaining_bytes());

    std::vector<uint8_t> narrowed(input);
    for (auto& v : narrowed) v &= (1 << frombits) - 1;
    std::vector<uint8_t> converted;
    bech32::convertbits(converted, narrowed, frombits, tobits, pad);

    std::vector<uint8_t> five;
    bech32::convertbits(five, input, 8, 5, true);
    if (five.size() + 3 + 6 <= 90) {
        for (auto encoding : {bech32::Encoding::BECH32, bech32::Encoding::BECH32M}) {
            const std::string encoded = bech32::encode("bc", five, encoding);
            assert(!encoded.empty());
            const auto r2 = bech32::decode(encoded);
            assert(r2.encoding == encoding);
            assert(r2.hrp == "bc");
            assert(r2.data == five);
        }
    }
    return 0;
}
