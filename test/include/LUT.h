//
// Created by leonard on 10.05.21.
//

#ifndef FBS_LUT_H
#define FBS_LUT_H

#include "fbscontext.h"
#include <functional>

bool run_lut_tests(std::vector<uint32_t>& bits);

class SwitchingKey {
public:
    SwitchingKey(std::shared_ptr<fbscrypto::RingGSWCryptoParams>& params, fbscrypto::LWEPrivateKey& pt_sk, lbcrypto::NativePoly& sk_poly);

    std::shared_ptr<fbscrypto::RingGSWCiphertext> keyswitch(fbscrypto::LWECiphertext& ct);

    std::shared_ptr<fbscrypto::RingGSWCiphertext> functional_keyswitch(fbscrypto::LWECiphertext& ct);

private:

    std::shared_ptr<fbscrypto::RingGSWCryptoParams> params;
    std::vector<std::vector<std::shared_ptr<fbscrypto::RingGSWCiphertext>>> KSK;
    std::vector<std::vector<std::shared_ptr<fbscrypto::RingGSWCiphertext>>> F_KSK;

    fbscrypto::LWEPrivateKey key;
    lbcrypto::NativePoly sk_poly;

};

class VerticalLUT {

public:

    VerticalLUT(std::shared_ptr<fbscrypto::RingGSWCryptoParams>& params, SwitchingKey& key,  uint32_t target_bits, std::function<uint64_t(uint64_t)>&);

    shared_ptr<fbscrypto::RingGSWCiphertext> evaluate(fbscrypto::FBSFHEContext& ctx, std::vector<fbscrypto::LWECiphertext>& bits);

private:

    uint32_t rem_bits;
    SwitchingKey& key;
    std::vector<lbcrypto::NativePoly> polyPowers;
    std::shared_ptr<fbscrypto::RingGSWCryptoParams> params;
    std::function<uint64_t(uint64_t)> F;
    std::vector<std::shared_ptr<fbscrypto::RingGSWCiphertext>> LUT_entries;

};

class HorizontalLUT {

public:

    HorizontalLUT(std::shared_ptr<fbscrypto::RingGSWCryptoParams>& params, SwitchingKey& key, uint32_t target_bits, std::vector<std::function<uint64_t(uint64_t)>>&);

    std::shared_ptr<fbscrypto::RingGSWCiphertext> evaluate(fbscrypto::FBSFHEContext &ctx, std::vector<fbscrypto::LWECiphertext>& bits);

private:

    SwitchingKey& key;
    std::shared_ptr<fbscrypto::RingGSWCryptoParams> params;
    std::vector<std::function<uint64_t(uint64_t)>> V_F;
    std::vector<std::shared_ptr<fbscrypto::RingGSWCiphertext>> LUT_entries;

};

#endif //FBS_LUT_H
