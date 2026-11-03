// The fixed spend key and serial context the coin harness identifies coins against. Nothing is random:
// the same input always runs against the same keys.
#pragma once

#include "libspark/coin.h"
#include "libspark/keys.h"

#include <vector>

namespace coin_stmt {

struct Keys {
    spark::SpendKey spend_key;
    spark::FullViewKey full_view_key;
    spark::IncomingViewKey incoming_view_key;
    std::vector<unsigned char> serial_context;

    explicit Keys(const spark::Params* params)
        : spend_key(params, Scalar(uint64_t(0x46495230534b))),
          full_view_key(spend_key),
          incoming_view_key(full_view_key),
          serial_context(32)
    {
        for (size_t i = 0; i < serial_context.size(); i++) {
            serial_context[i] = static_cast<unsigned char>(0xa0 + i);
        }
    }
};

} // namespace coin_stmt
