//
// Created by leonard on 07.05.21.
//

#ifndef FBS_SETUP_H
#define FBS_SETUP_H

#include "fbscontext.h"
#include "lwe.h"

struct CryptoData {

    CryptoData(fbscrypto::FBSFHEPARAMSET set) : ctx(), set(set) {
        ctx.GenerateFDFHEContext(set);
        key = ctx.KeyGen();
        ctx.BTKeyGen(key);
    }

    fbscrypto::FBSFHEContext ctx;
    fbscrypto::LWEPrivateKey key;
    fbscrypto::FBSFHEPARAMSET set;

};

static std::shared_ptr<fbscrypto::LWECiphertextImpl> add_ciphertexts(const std::shared_ptr<const fbscrypto::LWECiphertextImpl>& a,
                                                              const std::shared_ptr<const fbscrypto::LWECiphertextImpl>& b) {

    auto q = a->GetA().GetModulus();
    auto n = a->GetA().GetLength();

    auto v = NativeVector(n, q);
    for(uint32_t i = 0; i < n; i++) {
        v[i] = a->GetA(i).ModAddFast(b->GetA(i), q);
    }

    auto bnew = a->GetB().ModAddFast(b->GetB(), q);

    return std::make_shared<fbscrypto::LWECiphertextImpl>(v, bnew);
}

static std::shared_ptr<fbscrypto::LWECiphertextImpl> sub_ciphertexts(const std::shared_ptr<const fbscrypto::LWECiphertextImpl>& a,
                                                              const std::shared_ptr<const fbscrypto::LWECiphertextImpl>& b) {

    auto q = a->GetA().GetModulus();
    auto n = a->GetA().GetLength();

    auto v = NativeVector(n, q);
    for(uint32_t i = 0; i < n; i++) {
        v[i] = a->GetA(i).ModSubFast(b->GetA(i), q);
    }

    auto bnew = a->GetB().ModSubFast(b->GetB(), q);

    return std::make_shared<fbscrypto::LWECiphertextImpl>(v, bnew);

}


static std::shared_ptr<fbscrypto::LWECiphertextImpl> scale_ciphertexts(const std::shared_ptr<fbscrypto::LWECiphertextImpl>& a,
                                                                     uint32_t scale) {

    auto q = a->GetA().GetModulus();
    auto n = a->GetA().GetLength();

    auto v = NativeVector(n, q);
    auto mu = q.ComputeMu();
    for(uint32_t i = 0; i < n; i++) {
        v[i] = a->GetA(i).ModMulFast(scale, q, mu);
    }

    auto bnew = a->GetB().ModMulFast(scale, q, mu);

    return std::make_shared<fbscrypto::LWECiphertextImpl>(v, bnew);
}

#endif //FBS_SETUP_H
