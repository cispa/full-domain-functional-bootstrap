//
// Created by leonard on 10.05.21.
//

#include "LUT.h"
#include "setup.h"

void RLWEDecompose(std::shared_ptr<fbscrypto::RingGSWCryptoParams>& params, std::vector<std::pair<lbcrypto::NativePoly, lbcrypto::NativePoly>>& output,
                   lbcrypto::NativePoly accuA, lbcrypto::NativePoly accuB) {

    uint32_t N = params->GetLWEParams()->GetN();
    uint32_t baseG = params->GetBaseG();

    for(auto & pair_i : output) {
        for(uint32_t j = 0; j < N; j++) {
            pair_i.first[j] = accuA[j] % baseG;
            pair_i.second[j] = accuB[j] % baseG;

            accuA[j] /= baseG;
            accuB[j] /= baseG;
        }

        pair_i.first.SetFormat(EVALUATION);
        pair_i.second.SetFormat(EVALUATION);
    }

}


std::shared_ptr<fbscrypto::RingGSWCiphertext> CMUX(std::shared_ptr<fbscrypto::RingGSWCryptoParams>& params, fbscrypto::RingGSWCiphertext& bit,
                                                   std::shared_ptr<fbscrypto::RingGSWCiphertext>& A,
                                                   std::shared_ptr<fbscrypto::RingGSWCiphertext>& B,
                                                   std::vector<std::pair<lbcrypto::NativePoly, lbcrypto::NativePoly>>& decomp_buffer) {

    uint32_t digits = params->GetDigitsG();
    auto result = std::make_shared<fbscrypto::RingGSWCiphertext>(1, 2);

    auto d_A = (*A)[0][0] - (*B)[0][0];
    auto d_B = (*A)[0][1] - (*B)[0][1];

    (*result)[0][0] = (*B)[0][0];
    (*result)[0][1] = (*B)[0][1];

    d_A.SetFormat(COEFFICIENT);
    d_B.SetFormat(COEFFICIENT);

    RLWEDecompose(params, decomp_buffer, d_A, d_B);

    for(uint32_t i = 0; i < digits; i++) {

        auto& dA = decomp_buffer[i].first;
        auto& dB = decomp_buffer[i].second;

        auto& bL = bit[2 * i];
        auto& bR = bit[2 * i + 1];
;

        (*result)[0][0] += dA * bL[0]
                + dB * bR[0];
        (*result)[0][1] += dA * bL[1]
                + dB * bR[1];

        dA.SetFormat(COEFFICIENT);
        dB.SetFormat(COEFFICIENT);

    }

    return result;
}

SwitchingKey::SwitchingKey(std::shared_ptr<fbscrypto::RingGSWCryptoParams> &params, fbscrypto::LWEPrivateKey &pt_sk,
                           lbcrypto::NativePoly &sk_poly) :
                           params(params), KSK(params->GetLWEParams()->Getn()), F_KSK(params->GetLWEParams()->GetN() + 1), key(pt_sk), sk_poly(sk_poly) {

    sk_poly.SetFormat(EVALUATION);
    auto base = params->GetBaseG();
    auto digits = params->GetDigitsG();
    auto n = params->GetLWEParams()->Getn();
    NativeInteger Q = params->GetLWEParams()->GetQ();
    lbcrypto::DiscreteUniformGeneratorImpl<NativeVector> dug;

    // create "normal" switchkey
    for(uint32_t i = 0; i < n; i++) {
        std::vector<std::shared_ptr<fbscrypto::RingGSWCiphertext>> row(digits);
        auto m = lbcrypto::NativePoly(params->GetPolyParams(), COEFFICIENT, true);
        auto si = key->GetElement().at(i);
        m[0] = si > 1 ? Q - 1 : si;
        m.SetFormat(EVALUATION);

        for (uint32_t j = 0; j < digits; j++) {
            auto a = lbcrypto::NativePoly(dug, params->GetPolyParams(), EVALUATION);
            //auto a = fbscrypto::NativePoly(params->GetPolyParams(), EVALUATION, true);
            auto b = m + a * sk_poly;
            row[j] = std::make_shared<fbscrypto::RingGSWCiphertext>(1,2);
            (*row[j])[0][0] = std::move(a);
            (*row[j])[0][1] = std::move(b);
            m *= base;
        }
        KSK[i] = std::move(row);
    }

    // create function keyswitch key
    std::vector<std::shared_ptr<fbscrypto::RingGSWCiphertext>> row(digits);
    NativeInteger m = 1;

    for (uint32_t j = 0; j < digits; j++) {
        auto a = lbcrypto::NativePoly( params->GetPolyParams(), COEFFICIENT, true);
        a[0] = m;
        a.SetFormat(EVALUATION);
        auto b = lbcrypto::NativePoly(params->GetPolyParams(), EVALUATION, true);

        row[j] = std::make_shared<fbscrypto::RingGSWCiphertext>(1,2);
        (*row[j])[0][0] = std::move(a);
        (*row[j])[0][1] = std::move(b);
        m.ModMulFastEq(base, Q);
    }

    F_KSK[0] = std::move(row);

    for(uint32_t i = 1; i < n + 1; i++) {
        std::vector<std::shared_ptr<fbscrypto::RingGSWCiphertext>> row(digits);
        m = key->GetElement().at(i);
        for (uint32_t j = 0; j < digits; j++) {
            auto a = lbcrypto::NativePoly( params->GetPolyParams(), COEFFICIENT, true);
            a[0] = m;
            a.SetFormat(EVALUATION);
            auto b = lbcrypto::NativePoly(params->GetPolyParams(), EVALUATION, true);;
            row[j] = std::make_shared<fbscrypto::RingGSWCiphertext>(1,2);
            (*row[j])[0][0] = std::move(a);
            (*row[j])[0][1] = std::move(b);
            m.ModMulFastEq(base, Q);
        }

        F_KSK[i] = std::move(row);
    }
}

std::shared_ptr<fbscrypto::RingGSWCiphertext> SwitchingKey::keyswitch(fbscrypto::LWECiphertext &ct) {

    auto base = params->GetBaseG();
    auto digits = params->GetDigitsG();
    auto n = params->GetLWEParams()->Getn();

    auto result = std::make_shared<fbscrypto::RingGSWCiphertext>(1, 2);

    (*result)[0][0] = lbcrypto::NativePoly(params->GetPolyParams(), EVALUATION, true);
    (*result)[0][1] = lbcrypto::NativePoly(params->GetPolyParams(), COEFFICIENT, true);

    (*result)[0][1][0] = ct->GetB();
    (*result)[0][1].SetFormat(EVALUATION);

    for(uint32_t i = 0; i < n; i++) {
        auto coef = ct->GetA(i).ConvertToInt();
        auto row = KSK[i];

        for(uint32_t j = 0; j < digits; j++, coef /= base) {
            int64_t a0 = coef % base;
            if (a0 != 0) {
                auto& sample = row[j];
                (*result)[0][0] -= a0 * (*sample)[0][0];
                (*result)[0][1] -= a0 * (*sample)[0][1];
            }
        }
    }

    return result;
}

std::shared_ptr<fbscrypto::RingGSWCiphertext> SwitchingKey::functional_keyswitch(fbscrypto::LWECiphertext &ct) {

    auto base = params->GetBaseG();
    auto digits = params->GetDigitsG();
    auto n = params->GetLWEParams()->Getn();

    auto result = std::make_shared<fbscrypto::RingGSWCiphertext>(1, 2);

    (*result)[0][0] = lbcrypto::NativePoly(params->GetPolyParams(), EVALUATION, true);
    (*result)[0][1] = lbcrypto::NativePoly(params->GetPolyParams(), EVALUATION, true);

    auto b = ct->GetB().ConvertToInt();
    auto b_row = F_KSK[0];
    for(uint32_t i = 0; i < digits; i++, b /= base) {
        int64_t rem = b % base;
        if (rem != 0) {
            auto sampl = b_row[i];
            (*result)[0][0] += rem * (*sampl)[0][0];
            (*result)[0][1] += rem * (*sampl)[0][1];
        }
    }

    for(uint32_t i = 1; i < n + 1; i++) {
        auto coef = ct->GetA(i - 1).ConvertToInt();
        auto row = F_KSK[i];

        for(uint32_t j = 0; j < digits; j++, coef /= base) {
            int64_t a0 = coef % base;
            if (a0 != 0) {
                auto& sample = row[j];
                (*result)[0][0] -= a0 * (*sample)[0][0];
                (*result)[0][1] -= a0 * (*sample)[0][1];
            }
        }
    }

    return result;
}

VerticalLUT::VerticalLUT(std::shared_ptr<fbscrypto::RingGSWCryptoParams> &params, SwitchingKey& key, uint32_t target_bits, std::function<uint64_t(uint64_t)>& F) : params(params), key(key) {

    auto N = params->GetLWEParams()->GetN();
    uint32_t N_log2 = std::log2((long double)N);
    rem_bits = N_log2 >= target_bits ? 0 : target_bits - N_log2;

    for(uint32_t i = 0; i < (1 << rem_bits); i++) {
        auto ct = std::make_shared<fbscrypto::RingGSWCiphertext>(1,2);
        (*ct)[0][0] = lbcrypto::NativePoly(params->GetPolyParams(), COEFFICIENT, true);
        (*ct)[0][1] = lbcrypto::NativePoly(params->GetPolyParams(), COEFFICIENT, true);
        for(uint32_t j = 0; j < N; j++) {
            (*ct)[0][1][j] = F(i * N + j);
        }
        ct->SetFormat(EVALUATION);
        LUT_entries.push_back(ct);
    }

    for(uint32_t i = 0; i < N_log2; i++) {
        lbcrypto::NativePoly p(params->GetPolyParams(), COEFFICIENT, true);
        uint32_t coef = 2 * N - (1 << i);
        if (coef >= N) {
            p[coef % N] = params->GetLWEParams()->GetQ() - 1;
        } else {
            p[coef % N] = 1;
        }
        p.SetFormat(EVALUATION);
        polyPowers.push_back(p);
    }
}

shared_ptr<fbscrypto::RingGSWCiphertext> VerticalLUT::evaluate(fbscrypto::FBSFHEContext& ctx, std::vector<fbscrypto::LWECiphertext> &bits) {

    auto base = params->GetBaseG();
    auto digits = params->GetDigitsG();

    auto N = params->GetLWEParams()->GetN();
    uint32_t N_log2 = std::log2((long double)N);

    // keyswitch LWE -> RGSW
    std::vector<std::shared_ptr<fbscrypto::RingGSWCiphertext>> bits_RGSW;
    auto dummy = ctx.EncryptNoiseless((params->GetLWEParams()->Getq() >> 3).ConvertToInt());
    NativeInteger coef = 1;
    for(uint32_t i = 0; i < bits.size(); i++) {

        std::shared_ptr<fbscrypto::RingGSWCiphertext> bit_RGSW = std::make_shared<fbscrypto::RingGSWCiphertext>(2 * digits, 2);

        for(uint32_t j = 0; j < digits; j++) {
            // bootstrap and scale
            // In the original version "https://eprint.iacr.org/2017/430.pdf"
            // The authors combine the bootstrap and the scale step by modifying the rotation polynomial
            // As we are only interested in timings, we perform the bootstrap, ignore the result, and just scale the LWE sample
            volatile auto bst_dummy = ctx.BootstrapBinary(dummy);
            //\\ RLWE(m)
            auto switched = key.keyswitch(bits[i]);
            //\\ RLWE(-sm)
            auto f_switched = key.functional_keyswitch(bits[i]);

            (*bit_RGSW)[2 * j][0] = std::move((*f_switched)[0][0]);
            (*bit_RGSW)[2 * j][1] = std::move((*f_switched)[0][1]);
            (*bit_RGSW)[2 * j + 1][0] = std::move((*switched)[0][0]);
            (*bit_RGSW)[2 * j + 1][1] = std::move((*switched)[0][1]);

            bits[i] = std::make_shared<fbscrypto::LWECiphertextImpl>(bits[i]->GetA() * base, bits[i]->GetB().ModMulFast(base, params->GetLWEParams()->GetQ()));
        }
        bit_RGSW->SetFormat(EVALUATION);
        bits_RGSW.push_back(bit_RGSW);
    }

    std::vector<std::pair<lbcrypto::NativePoly, lbcrypto::NativePoly>> decomp_buffer(digits);
    for(auto& pair : decomp_buffer) {
        pair.first = lbcrypto::NativePoly(params->GetPolyParams(), COEFFICIENT, true);
        pair.second = lbcrypto::NativePoly(params->GetPolyParams(), COEFFICIENT, true);
    }

    for(uint32_t i = 0; i < rem_bits; i++) {
        std::vector<std::shared_ptr<fbscrypto::RingGSWCiphertext>> new_LUT;

        for(uint32_t j = 0; j < LUT_entries.size(); j += 2) {
            new_LUT.push_back(CMUX(params, *(bits_RGSW[i]), LUT_entries[j + 1], LUT_entries[j], decomp_buffer));
        }

        LUT_entries = std::move(new_LUT);

    }

    auto rotation_poly = LUT_entries[0];
    rotation_poly->SetFormat(EVALUATION);
    int start;
    if (rem_bits == 0)
        start = bits_RGSW.size() - 1;
    else
        start = N_log2 - 1;

    for(int i = start; i >= 0; i--) {
        auto case0 = rotation_poly;

        auto& poly = polyPowers[i];

        auto case1 = std::make_shared<fbscrypto::RingGSWCiphertext>(1, 2);
        (*case1)[0][0] = (*case0)[0][0] * poly;
        (*case1)[0][1] = (*case0)[0][1] * poly;

        rotation_poly = CMUX(params, *bits_RGSW[i], case1, case0, decomp_buffer);
    }

    return rotation_poly;
}

HorizontalLUT::HorizontalLUT(std::shared_ptr<fbscrypto::RingGSWCryptoParams> &params, SwitchingKey& key, uint32_t target_bits, std::vector<std::function<uint64_t(uint64_t)>>& V_F) :
V_F(V_F), key(key),params(params) {
    for(uint32_t i = 0; i < (1 << target_bits); i++) {
        auto ct = std::make_shared<fbscrypto::RingGSWCiphertext>(1,2);
        (*ct)[0][0] = lbcrypto::NativePoly(params->GetPolyParams(), COEFFICIENT, true);
        (*ct)[0][1] = lbcrypto::NativePoly(params->GetPolyParams(), COEFFICIENT, true);
        for(uint32_t j = 0; j < V_F.size(); j++) {
            (*ct)[0][1][j] = V_F[j](i);
        }
        ct->SetFormat(EVALUATION);
        LUT_entries.push_back(ct);
    }
}

std::shared_ptr<fbscrypto::RingGSWCiphertext> HorizontalLUT::evaluate(fbscrypto::FBSFHEContext& ctx, std::vector<fbscrypto::LWECiphertext> &bits) {

    auto base = params->GetBaseG();
    auto digits = params->GetDigitsG();

    // keyswitch LWE -> RGSW
    std::vector<std::shared_ptr<fbscrypto::RingGSWCiphertext>> bits_RGSW;
    auto dummy = ctx.EncryptNoiseless((params->GetLWEParams()->Getq() >> 3).ConvertToInt());

    for(uint32_t i = 0; i < bits.size(); i++) {

        std::shared_ptr<fbscrypto::RingGSWCiphertext> bit_RGSW = std::make_shared<fbscrypto::RingGSWCiphertext>(2 * digits, 2);

        for(uint32_t j = 0; j < digits; j++) {
            // bootstrap and scale
            // In the original version "https://eprint.iacr.org/2017/430.pdf"
            // The authors combine the bootstrap and the scale step by modifying the rotation polynomial
            // As we are only interested in timings, we perform the bootstrap, ignore the result, and just scale the LWE sample
            volatile auto bst_dummy = ctx.BootstrapBinary(dummy);
            //\\ RLWE(m)
            auto switched = key.keyswitch(bits[i]);
            //\\ RLWE(-sm)
            auto f_switched = key.functional_keyswitch(bits[i]);

            (*bit_RGSW)[2 * j][0] = std::move((*f_switched)[0][0]);
            (*bit_RGSW)[2 * j][1] = std::move((*f_switched)[0][1]);
            (*bit_RGSW)[2 * j + 1][0] = std::move((*switched)[0][0]);
            (*bit_RGSW)[2 * j + 1][1] = std::move((*switched)[0][1]);


            bits[i] = std::make_shared<fbscrypto::LWECiphertextImpl>(bits[i]->GetA() * base, bits[i]->GetB().ModMulFast(base, params->GetLWEParams()->GetQ()));
        }

        bits_RGSW.push_back(bit_RGSW);
    }

    std::vector<std::pair<lbcrypto::NativePoly, lbcrypto::NativePoly>> decomp_buffer(digits);

    // decomposition buffer for CMUX
    for(auto& pair : decomp_buffer) {
        pair.first = lbcrypto::NativePoly(params->GetPolyParams(), COEFFICIENT, true);
        pair.second = lbcrypto::NativePoly(params->GetPolyParams(), COEFFICIENT, true);
    }

    for(uint32_t i = 0; i < bits_RGSW.size(); i++) {
        std::vector<std::shared_ptr<fbscrypto::RingGSWCiphertext>> new_LUT;

        for(uint32_t j = 0; j < LUT_entries.size(); j += 2) {
            new_LUT.push_back(CMUX(params, *(bits_RGSW[i]), LUT_entries[j + 1], LUT_entries[j], decomp_buffer));
        }

        LUT_entries = std::move(new_LUT);

    }

    return LUT_entries[0];
}

struct LweToRLWESwitchKey {


    LweToRLWESwitchKey(const std::shared_ptr<fbscrypto::RingGSWCryptoParams>& params,
                       std::shared_ptr<fbscrypto::LWEPrivateKeyImpl>& lwekey,
                       std::shared_ptr<fbscrypto::LWEPrivateKeyImpl>& ringKey) : samples(params->GetLWEParams()->Getn()) {

        auto skPoly = lbcrypto::NativePoly(params->GetPolyParams(), COEFFICIENT, true);
        skPoly.SetValues(ringKey->GetElement(), COEFFICIENT);

        skPoly.SetFormat(EVALUATION);

        auto base = params->GetBaseG();
        auto digits = params->GetDigitsG();
        auto n = params->GetLWEParams()->Getn();
        NativeInteger q = params->GetLWEParams()->Getq();
        NativeInteger Q = params->GetLWEParams()->GetQ();
        lbcrypto::DiscreteUniformGeneratorImpl<NativeVector> dug;
        dug.SetModulus(Q);

        for(uint32_t i = 0; i < n; i++) {
            std::vector<fbscrypto::RingGSWCiphertext> row(digits);
            auto m = lbcrypto::NativePoly(params->GetPolyParams(), COEFFICIENT, true);
            auto si = lwekey->GetElement().at(i);
            m[0] = si > 1 ? Q - 1 : si;
            m.SetFormat(EVALUATION);

            for (uint32_t j = 0; j < digits; j++) {
                auto a = lbcrypto::NativePoly(dug, params->GetPolyParams(), EVALUATION);
                //auto a = fbscrypto::NativePoly(params->GetPolyParams(), EVALUATION, true);
                auto b = m + a * skPoly;
                row[j] = fbscrypto::RingGSWCiphertext(1,2);
                row[j][0][0] = std::move(a);
                row[j][0][1] = std::move(b);
                m *= base;
            }

            samples[i] = std::move(row);

        }
    }

    std::shared_ptr<fbscrypto::RingGSWCiphertext> switchKey(const std::shared_ptr<fbscrypto::RingGSWCryptoParams>& params,
                                                           std::shared_ptr<fbscrypto::LWECiphertextImpl>& ct) {

        auto base = params->GetBaseG();
        auto digits = params->GetDigitsG();
        auto n = params->GetLWEParams()->Getn();

        auto& a = ct->GetA();
        auto& b = ct->GetB();

        auto result = std::make_shared<fbscrypto::RingGSWCiphertext>(1 , 2);

        (*result)[0][0] = lbcrypto::NativePoly(params->GetPolyParams(), EVALUATION, true);
        (*result)[0][1] = lbcrypto::NativePoly(params->GetPolyParams(), COEFFICIENT, true);

        (*result)[0][1][0] = b;
        (*result)[0][1].SetFormat(EVALUATION);

        for(uint32_t i = 0; i < n; i++) {

            auto coef = a[i].ConvertToInt();
            auto row = samples[i];

            for(uint32_t j = 0; j < digits; j++, coef /= base) {
                auto a0 = coef % base;
                if (a0 != 0) {
                    auto& sample = row[j];
                    (*result)[0][0] -= a0 * sample[0][0];
                    (*result)[0][1] -= a0 * sample[0][1];
                }
            }

        }

        return result;
    }

    std::vector<std::vector<fbscrypto::RingGSWCiphertext>> samples;

};

std::shared_ptr<fbscrypto::LWECiphertextImpl> genLWESample(uint32_t bit, NativeInteger Q, uint32_t N) {
    NativeVector a(N, Q);

    for(uint32_t i = 0; i < N; i++)
        a[i] = 0;

    NativeInteger b = bit;

    return std::make_shared<fbscrypto::LWECiphertextImpl>(a,b);
}

uint64_t time_horizontal_lut(fbscrypto::FBSFHEContext& ctx, uint32_t bits) {
    auto key = ctx.KeyGen();
    auto keyN = ctx.KeyGenN();
    auto params = ctx.GetParams();
    auto Q = params->GetLWEParams()->GetQ();
    auto n = params->GetLWEParams()->Getn();
    auto space = (1 << bits);

    auto msg = rand() % space;
    auto msg_copy = msg;
    // message to be evaluated

    // generate refreshing key
    ctx.BTKeyGen(key);

    // create sk poly
    auto skPoly = lbcrypto::NativePoly(params->GetPolyParams(), COEFFICIENT, true);
    skPoly.SetValues(keyN->GetElement(), COEFFICIENT);


    skPoly.SetFormat(EVALUATION);


    // build ksk
    SwitchingKey sKey(params, key, skPoly);
    auto sample = genLWESample(1234, Q, n);

    // set functions
    auto F = [](uint64_t a) { return a;};
    std::vector<std::function<uint64_t(uint64_t)>> V_F = {F};

    // build lut
    HorizontalLUT HLUT(params, sKey, bits, V_F);

    // build bits
    std::vector<std::shared_ptr<fbscrypto::LWECiphertextImpl>> messages;
    for(uint32_t i = 0; i < bits; i++) {
        messages.push_back(genLWESample(msg & 1, Q, n));
        msg >>= 1;
    }

    auto start = std::chrono::high_resolution_clock::now();

    auto output = HLUT.evaluate(ctx, messages);
    auto result = (*output)[0][1] - skPoly * (*output)[0][0];

    auto stop = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(stop-start).count();

    result.SetFormat(COEFFICIENT);

    return elapsed;
}

uint64_t time_vertical_lut(fbscrypto::FBSFHEContext& ctx, uint32_t bits) {
    auto key = ctx.KeyGen();
    auto keyN = ctx.KeyGenN();
    auto params = ctx.GetParams();
    auto Q = params->GetLWEParams()->GetQ();
    auto n = params->GetLWEParams()->Getn();
    auto space = (1 << bits);

    auto msg = rand() % space;
    auto msg_copy = msg;
    // message to be evaluated

    // generate refreshing key
    ctx.BTKeyGen(key);

    // create sk poly
    auto skPoly = lbcrypto::NativePoly(params->GetPolyParams(), COEFFICIENT, true);
    skPoly.SetValues(keyN->GetElement(), COEFFICIENT);

    skPoly.SetFormat(EVALUATION);

    // build ksk
    SwitchingKey sKey(params, key, skPoly);
    auto sample = genLWESample(1234, Q, n);

    // set functions
    std::function<uint64_t(uint64_t)> F = [](uint64_t a) { return a;};
;

    // build lut
    VerticalLUT VLUT(params, sKey, bits, F);

    // build bits
    std::vector<std::shared_ptr<fbscrypto::LWECiphertextImpl>> messages;
    for(uint32_t i = 0; i < bits; i++) {
        messages.push_back(genLWESample(msg & 1, Q, n));
        msg >>= 1;
    }

    auto start = std::chrono::high_resolution_clock::now();

    auto output = VLUT.evaluate(ctx, messages);
    auto result = (*output)[0][1] - skPoly * (*output)[0][0];

    auto stop = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(stop-start).count();

    result.SetFormat(COEFFICIENT);

    return elapsed;
}

bool run_lut_tests(std::vector<uint32_t>& bits) {

    std::vector<fbscrypto::FBSFHEPARAMSET> sets = {fbscrypto::FBSFHEPARAMSET::TFHE_80_2, fbscrypto::FBSFHEPARAMSET::TFHE_100_2};

    for(auto& c_set : sets) {
        fbscrypto::FBSFHEContext ctx;
        ctx.GenerateFDFHEContext(c_set);
        std::cout << "# Testing for parameter set " << static_cast<int>(c_set) << std::endl << std::endl;
        std::cout << "Horizontal LUT: " << std::endl;
        for(auto& b : bits) {
            auto el = time_horizontal_lut(ctx, b);
            std::cout << "[" << b / 2 << ", " << b << "]  bits took " << el << "ms" << std::endl;
        }
        std::cout << std::endl << "Vertical LUT: " << std::endl;
        for(auto& b : bits) {
            auto el = time_vertical_lut(ctx, b);
            std::cout << "[" << b / 2 << ", " << b << "]  bits took " << el << "ms" << std::endl;
        }
        std::cout << std::endl;
    }

    return true;
}
