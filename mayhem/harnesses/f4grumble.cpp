#include "libspark/f4grumble.h"

#include <cassert>
#include <cstdint>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* buf, size_t len)
{
    if (len == 0) return 0;

    const unsigned char network = buf[0];
    const std::vector<unsigned char> input(buf, buf + len);

    if (len > spark::F4Grumble::get_max_size()) {
        bool thrown = false;
        try {
            spark::F4Grumble g(network, len);
        } catch (const std::exception&) {
            thrown = true;
        }
        assert(thrown);
        return 0;
    }

    spark::F4Grumble grumble(network, len);
    std::vector<unsigned char> scrambled = grumble.encode(input);
    std::vector<unsigned char> unscrambled = grumble.decode(scrambled);
    assert(scrambled.size() == input.size());
    assert(unscrambled == input);

    const unsigned char evil_network = ~network;
    spark::F4Grumble evil(evil_network, len);
    std::vector<unsigned char> evil_unscrambled = evil.decode(scrambled);
    assert(evil_unscrambled.size() == scrambled.size());
    assert(evil_unscrambled != input);
    return 0;
}
