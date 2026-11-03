// Minimal stand-in for src/test/test_bitcoin.h: the libspark suites only use BasicTestingSetup as an
// empty fixture, while the real header drags in the whole node (chainparams, wallet, leveldb, ...).
#pragma once

struct BasicTestingSetup {
};
