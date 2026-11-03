#include "common.h"
#include "libspark/aead.h"
#include "streams.h"
#include "version.h"

#include <cassert>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* buf, size_t len)
{
    FuzzedDataProvider fdp(buf, len);

    GroupElement key = fz_group_element(fdp);
    int message = fdp.ConsumeIntegral<int>();
    std::string additional_data = fdp.ConsumeRemainingBytesAsString();

    CDataStream ser(SER_NETWORK, PROTOCOL_VERSION);
    ser << message;

    spark::AEADEncryptedData aed = spark::AEAD::encrypt(key, additional_data, ser);
    ser = spark::AEAD::decrypt_and_verify(key, additional_data, aed);
    int received;
    ser >> received;
    assert(message == received);
    return 0;
}
