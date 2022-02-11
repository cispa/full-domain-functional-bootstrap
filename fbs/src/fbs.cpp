//
// Created by leonard on 06.05.21.
//

#include "fhew.h"


namespace fbscrypto {

    void RLWEDecompose(std::shared_ptr<RingGSWCryptoParams>& params, std::vector<std::pair<lbcrypto::NativePoly, lbcrypto::NativePoly>>& output,
                       lbcrypto::NativePoly accuA, lbcrypto::NativePoly accuB) {

        uint32_t N = params->GetLWEParams()->GetN();
        uint32_t baseG = params->GetBaseG();
        // assume baseG is a power of 2
        uint32_t modmask = baseG - 1;
        uint32_t shift = std::log2(baseG);

        for(auto & pair_i : output) {
            for(uint32_t j = 0; j < N; j++) {
                pair_i.first[j] = accuA[j].ConvertToInt() & modmask;
                pair_i.second[j] = accuB[j].ConvertToInt() & modmask;

                accuA[j] >>= shift;
                accuB[j] >>= shift;
            }

            pair_i.first.SetFormat(EVALUATION);
            pair_i.second.SetFormat(EVALUATION);
        }

    }

    void CMUX(std::shared_ptr<RingGSWCryptoParams>& params, RingGSWCiphertext& bit, std::shared_ptr<RingGSWCiphertext>& accu,
              std::vector<std::pair<lbcrypto::NativePoly, lbcrypto::NativePoly>>& decomp_buffer, uint32_t a) {

        uint32_t digits = params->GetDigitsG();

        auto xA = params->GetMonomial(a);

        auto accuxA = (*accu)[0][0] * xA;
        auto accuxB =  (*accu)[0][1] * xA;

        accuxA.SetFormat(COEFFICIENT);
        accuxB.SetFormat(COEFFICIENT);

        RLWEDecompose(params, decomp_buffer, accuxA, accuxB);

        for(uint32_t i = 0; i < digits; i++) {

            auto& dA = decomp_buffer[i].first;
            auto& dB = decomp_buffer[i].second;

            auto& bL = bit[2 * i];
            auto& bR = bit[2 * i + 1];

            (*accu)[0][0] += dA * bL[0] + dB * bR[0];
            (*accu)[0][1] += dA * bL[1] + dB * bR[1];

            // There is no method to "reset" a polynomial, therefore this has to do
            dA.SetValuesToZero();
            dB.SetValuesToZero();
            dA.SetValues(dA.GetValues(), COEFFICIENT);
            dB.SetValues(dB.GetValues(), COEFFICIENT);
        }
    }

    std::shared_ptr<RingGSWCiphertext> BlindRotate(std::shared_ptr<RingGSWCryptoParams> params, const RingGSWEvalKey& EK,
                                                   std::shared_ptr<RingGSWCiphertext> accu, const NativeVector& a) {

        auto& polyParams = params->GetPolyParams();
        auto digits = params->GetDigitsG();
        auto& BSK = EK.BSkey;
        auto lwe_type = params->GetLWEParams()->GetLweType();
        uint32_t N = params->GetLWEParams()->GetN();

        uint32_t n = params->GetLWEParams()->Getn();
        NativeInteger _2N = 2 * N;

        std::vector<std::pair<lbcrypto::NativePoly, lbcrypto::NativePoly>> decomp_buffer(digits);

        for(auto& pair : decomp_buffer) {
            pair.first = lbcrypto::NativePoly(polyParams, COEFFICIENT, true);
            pair.second = lbcrypto::NativePoly(polyParams, COEFFICIENT, true);
        }

#ifdef WITH_SECRET_KEY
        auto skPoly = lbcrypto::NativePoly(polyParams);
        skPoly.SetValues(EK.skN, COEFFICIENT);
        skPoly.SetFormat(EVALUATION);
#endif


        if (lwe_type == TERNARY) {

            for (uint32_t i = 0; i < n; i++) {
                CMUX(params, (*BSK)[0][0][i], accu, decomp_buffer, _2N.ModSub(a[i], _2N).ConvertToInt());
                CMUX(params, (*BSK)[0][1][i], accu, decomp_buffer, a[i].ConvertToInt());
            }

        } else {

            for(uint32_t i = 0; i < n; i++) {
/*
#ifdef WITH_SECRET_KEY
                auto dec_accu = (*accu)[0][1] - (*accu)[0][0] * skPoly;
                dec_accu.SetFormat(COEFFICIENT);
                auto dec_bit = (*BSK)[0][0][i][1][1] - (*BSK)[0][0][i][1][0] * skPoly;
                dec_bit.SetFormat(COEFFICIENT);
                std::cerr << "[CMUX " << i << " ][" << dec_bit[0] << "]" << dec_accu << std::endl;
#endif
 */
                CMUX(params, (*BSK)[0][0][i], accu, decomp_buffer, _2N.ModSub(a[i], _2N).ConvertToInt());

            }

        }
        return accu;
    }

    std::shared_ptr<RingGSWCiphertext> PubMux(const std::shared_ptr<RingGSWCryptoParams>& params, std::vector<RingGSWCiphertext>& powers_of_sig,
                                              lbcrypto::NativePoly& rotP0,
                lbcrypto::NativePoly& rotP1, BootstrapFunction& fct) {

        auto result = std::make_shared<RingGSWCiphertext>(1, 2);

        NativeInteger Q = params->GetLWEParams()->GetQ();
        // message space
        uint32_t t = fct.GetMessageSpace();
        // cyclotomic order
        uint32_t N = params->GetLWEParams()->GetN();
        // round(Q / t)
        NativeInteger deltaQt = Q.DivideAndRound(t);
        // bootstrap decomposition base
        uint32_t LBOOT = params->GetBaseBoot();
        uint32_t lBoot = params->GetDigitsBoot();

        std::vector<lbcrypto::NativePoly> R(lBoot);

        auto pcal = rotP1 - rotP0;
        (*result)[0][1] = deltaQt * rotP0;
        (*result)[0][1].SetFormat(EVALUATION);
        (*result)[0][0] = lbcrypto::NativePoly(params->GetPolyParams(), EVALUATION, true);

        for(auto& p : R) {
            p = lbcrypto::NativePoly(params->GetPolyParams(), COEFFICIENT, true);
        }

        pcal.SetFormat(COEFFICIENT);
        uint32_t mod_mask = LBOOT - 1;
        uint32_t shift_amount = std::log2(LBOOT);

        for (uint32_t i = 0; i < N; i++) {
            auto coef = pcal[i].ConvertToInt();

            for (uint32_t j = 0; j < lBoot; j++) {
                R[j][i] = coef & mod_mask;
                coef >>= shift_amount;
            }
        }

        for(auto& p : R) {
            p.SetFormat(EVALUATION);
        }

        for(uint32_t i = 0; i < lBoot; i++) {


            (*result)[0][0] += R[i] * powers_of_sig[i][0][0];
            (*result)[0][1] += R[i] * powers_of_sig[i][0][1];
        }

        return result;

    }

    std::vector<std::shared_ptr<LWECiphertextImpl>>
    RingGSWAccumulatorScheme::ComputePowersOfSig(const shared_ptr<RingGSWCryptoParams> &params,
                                                 const RingGSWEvalKey &EK,
                                                 lbcrypto::PolyImpl<NativeVector> &sgnP, const NativeVector64 &aN,
                                                 const NativeInteger &delta_Qt2) const {

        // zero polynomial for accumulation
        auto zero = lbcrypto::NativePoly(params->GetPolyParams(), EVALUATION, true);

        // read parameters
        NativeInteger Q = params->GetLWEParams()->GetQ();
        NativeInteger LBOOT = params->GetBaseBoot();
        NativeInteger lBOOT = params->GetDigitsBoot();
        NativeInteger mu = Q.ComputeMu();
        uint32_t N = params->GetLWEParams()->GetN();

        auto accu = std::make_shared<RingGSWCiphertext>(1, 2);

        std::vector<std::shared_ptr<LWECiphertextImpl>> powers_of_sig(lBOOT.ConvertToInt());

        // compute powers of sig
        NativeInteger power_of_LBOOT = delta_Qt2;

#ifdef WITH_SECRET_KEY
        auto skPoly = lbcrypto::NativePoly(params->GetPolyParams());
        skPoly.SetValues(EK.skN, Format::COEFFICIENT);
        skPoly.SetFormat(Format::EVALUATION);
#endif


        for(uint32_t i = 0; i < lBOOT.ConvertToInt(); i++) {
            // i-th power of sign as RLWE sample
            (*accu)[0][0] = zero;
            (*accu)[0][1] = sgnP;
            auto sig_pow_i = BlindRotate(params, EK, accu, aN);

            sig_pow_i->SetFormat(COEFFICIENT);
            NativeVector r_a(N, Q);
            NativeInteger r_b = power_of_LBOOT.ModAdd((*sig_pow_i)[0][1][0], Q);

            r_a[0] = (*sig_pow_i)[0][0][0];
            for(uint32_t j = 1; j < params->GetLWEParams()->GetN(); j++) {
                auto val = (*sig_pow_i)[0][0][N - j];
                r_a[j] = Q.ModSub(val, Q);
            }

            powers_of_sig[i] = std::make_shared<LWECiphertextImpl>(r_a, r_b);

#ifdef WITH_SECRET_KEY
            NativeInteger dec = r_b;
            for(uint32_t j = 0; j< params->GetLWEParams()->GetN(); j++) {
                auto prod = r_a.at(j).ModMul(EK.skN.at(j), Q);
                dec.ModSubFastEq(prod, Q);
            }

            sig_pow_i->SetFormat(EVALUATION);
            auto dec_poly = (*sig_pow_i)[0][1] - (*sig_pow_i)[0][0] * skPoly;
            dec_poly.SetFormat(COEFFICIENT);
            dec_poly += power_of_LBOOT;
            std::cerr << "Extracted poly " << dec_poly << std::endl;
            std::cerr << "Extracted LWE sample " << dec << std::endl;
            sgnP.SetFormat(COEFFICIENT);
            std::cerr << "Sign poly" << sgnP << std::endl;
            sgnP.SetFormat(EVALUATION);
#endif

            sgnP *= LBOOT;

            power_of_LBOOT.ModMulFastEq(LBOOT, Q, mu);
        }

        return powers_of_sig;
    }


    std::shared_ptr<RingGSWCiphertext> RingGSWAccumulatorScheme::BuildAcc(
            const std::shared_ptr<RingGSWCryptoParams>& params,
            const RingGSWEvalKey& EK,
            std::vector<std::shared_ptr<LWECiphertextImpl>>& powers_of_sig,
            lbcrypto::NativePoly& rotP0, lbcrypto::NativePoly& rotP1, BootstrapFunction& fct
            ) const {

        // ring mod
        NativeInteger Q = params->GetLWEParams()->GetQ();
        // bootstrap base
        uint32_t LBOOT = params->GetBaseBoot();
        // bootstrap dim
        uint32_t lBOOT = params->GetBaseBoot();
        // result of switch from LWE to RLWE
        std::vector<RingGSWCiphertext> switched;
        switched.reserve(lBOOT);

        for(auto& lwe : powers_of_sig) {
            switched.push_back(*RLWEKeySwitch(params, EK.RLWEKey, lwe));
        }

#ifdef WITH_SECRET_KEY
        for(auto& sample : switched) {
            auto dec = (sample)[0][1] - (sample)[0][0] * EK.RingPoly;
            dec.SetFormat(COEFFICIENT);
            std::cerr << dec << std::endl;
        }
#endif

        return PubMux(params, switched, rotP0, rotP1, fct);
    }


    std::pair<lbcrypto::NativePoly, lbcrypto::NativePoly> constructRotationPolynomial(const std::shared_ptr<RingGSWCryptoParams>& params, const BootstrapFunction& F) {

        auto rotP0 = lbcrypto::NativePoly(params->GetPolyParams(), COEFFICIENT, true);
        auto rotP1 = lbcrypto::NativePoly(params->GetPolyParams(), COEFFICIENT, true);

        auto T = F.GetMessageSpace();
        int Td2 = T >> 1;

        auto NF = params->GetLWEParams()->GetN();
        auto Q = params->GetLWEParams()->GetQ();

        int p = 2 * int(NF / T);
        int bound = NF / T;

        for(uint32_t i = 0; i < T; i++) {
            uint32_t center = i * p;

            for(int e = -bound; e < bound; e++) {
                int pos = (int(center) + e) % NF;
                if (center == 0) {
                    // ORIG rotP1[pos] = Q - F(TD2)
                    if (e == 0)
                        rotP0[pos] = (Q-F(Td2)) % Q;
                    else if (e > 0)
                        rotP0[pos] = F(0);
                    else
                        rotP1[pos] = (Q - F(0)) % Q;
                }
                else if(center > 0 && center < NF)
                    rotP1[NF - pos - 1] = (Q - F(i)) % Q;
                else if (center == NF) {
                    // ORIG rotP0[pos] = F(0);
                    if (e == 0)
                        rotP1[pos] = F(0);
                    else if (e > 0)
                        rotP1[pos] = (Q - F(Td2)) % Q;
                    else
                        rotP0[pos] = F(Td2);
                }
                else
                    rotP0[NF - pos - 1] = F(i);
            }
        }


        return std::make_pair(rotP0, rotP1);
    }

    std::vector<std::shared_ptr<LWECiphertextImpl>>
    RingGSWAccumulatorScheme::BootstrapMultipleFunctions(const std::shared_ptr<RingGSWCryptoParams> &params,
                                                         const RingGSWEvalKey &EK,
                                                         const std::shared_ptr<const LWECiphertextImpl> &ct1,
                                                         const std::shared_ptr<LWEEncryptionScheme> &LWEscheme,
                                                         std::vector<BootstrapFunction> &functions,
                                                         SKIP_STEP step) const {

        if (functions.empty()) {
            PALISADE_THROW(lbcrypto::config_error, "At least one functions needs to be provided to bootstrap.");
        }


        //\\ setup
        // load parameters
        NativeInteger q = params->GetLWEParams()->Getq();
        NativeInteger Q = params->GetLWEParams()->GetQ();

        uint32_t n = params->GetLWEParams()->Getn();
        uint32_t N = params->GetLWEParams()->GetN();
        uint32_t n_Fs = functions.size();

        if (ct1->GetA().GetLength() != n || ct1->GetA().GetModulus() != q) {
            PALISADE_THROW(lbcrypto::palisade_error, "Input not in bootstrappable format. Input should be fresh or result of bootstrap with \\step = NONE");
        }

        // induced values
        uint32_t T = functions.at(0).GetMessageSpace();
        NativeInteger delta_Qt2 = Q.DivideAndRound(T * 2);
        NativeInteger delta_Qt2N = Q.ModSubFast(delta_Qt2, Q);

        // temporary variables
        // used to multiply the rotation polys by X^modswitch(b, q, 2 * N)
        auto xB = lbcrypto::NativePoly(params->GetPolyParams(), COEFFICIENT, true);
        // contain modswitch(\vec{a}, q, 2 * N)
        auto aN = NativeVector(n, 2 * N);
        // sign polynomial for initial blind rotation
        auto sgnP = lbcrypto::NativePoly(params->GetPolyParams(), COEFFICIENT, true);
        // stores powers of sign

        // Modulo switch
        auto &a = ct1->GetA();
        auto b = ct1->GetB();

        for(uint32_t i = 0; i < n; i++) {
            aN[i] = a[i].MultiplyAndRound(2 * N, q);
        }

        uint64_t bN = b.MultiplyAndRound(2 * N, q).ConvertToInt();

        // set pre-blindrotate monomial and sign polynomial
        xB[bN % N] = bN < N ? 1 : Q-1;
        for(uint32_t i = 0; i < N; i++) {
            sgnP[i] = delta_Qt2N;
        }

        //\\ Actual work starts here
        // NTT mode
        xB.SetFormat(EVALUATION);
        sgnP.SetFormat(EVALUATION);

        // shift
        sgnP *= xB;
        
        // compute powers of sign
        TIME_SECTION_MILLIS("l_boot * Blindrotate", auto powers_of_sig = ComputePowersOfSig(params, EK, sgnP, aN, delta_Qt2));

        std::vector<std::shared_ptr<LWECiphertextImpl>> result(n_Fs);

        // apply all functions to input ciphertext
        for(uint32_t i = 0; i < n_Fs; i++) {

            // build accumulator for final bootstrap
            auto rotation_polys = constructRotationPolynomial(params, functions[i]);
            std::cout << rotation_polys.first << std::endl;
            std::cout << rotation_polys.second << std::endl;
            TIME_SECTION_MILLIS("FDB BuildAcc",auto accumulator = BuildAcc(params, EK, powers_of_sig, rotation_polys.first, rotation_polys.second, functions[i]));

#ifdef WITH_SECRET_KEY
            auto dec = (*accumulator)[0][1] - (*accumulator)[0][0] * EK.RingPoly;
            dec.SetFormat(COEFFICIENT);
            std::cerr << "Rotation poly = " << dec << std::endl;
#endif

            (*accumulator)[0][0] *= xB;
            (*accumulator)[0][1] *= xB;

             std::shared_ptr<LWECiphertextImpl> lwe = BootstrapInner(params, EK, LWEscheme, aN, accumulator, step);

            result[i] = lwe;
        }

        return result;

    }

    shared_ptr<LWECiphertextImpl>
    RingGSWAccumulatorScheme::BootstrapInner(const std::shared_ptr<RingGSWCryptoParams> &params,
                                             const RingGSWEvalKey &EK,
                                             const shared_ptr<LWEEncryptionScheme> &LWEscheme, const NativeVector64 &aN,
                                             std::shared_ptr<RingGSWCiphertext> &accumulator, SKIP_STEP step) const {// compute function via blind rotation

        TIME_SECTION_MILLIS("FDB BlindRotate", auto fi_res = BlindRotate(params, EK, accumulator, aN));

#ifdef WITH_SECRET_KEY
        auto dec = (*fi_res)[0][1] - (*fi_res)[0][0] * EK.RingPoly;
        dec.SetFormat(COEFFICIENT);
        std::cerr << "Accumulator after rotation = " << dec << std::endl;
#endif

        // extract LWE sample
        auto NTT_A = (*fi_res)[0][0].Transpose();
        auto NTT_B = (*fi_res)[0][1].Transpose();

        NTT_A.SetFormat(COEFFICIENT);
        NTT_B.SetFormat(COEFFICIENT);

        // back to the original ct space
        auto lwe_QN = std::make_shared<LWECiphertextImpl>(NTT_A.GetValues(), NTT_B[0]);

        if (step == KEYSWITCH)
            return lwe_QN;

        {
            TIME_SECTION_MILLIS("FDB Keyswitch", auto lwe_Q = LWEscheme->KeySwitch(params->GetLWEParams(), EK.KSkey, lwe_QN);)

            if (step == MODSWITCH)
                return lwe_Q;

            auto lwe = LWEscheme->ModSwitch(params->GetLWEParams(), lwe_Q);
            return lwe;
        }
    }


    std::shared_ptr<LWECiphertextImpl>
    RingGSWAccumulatorScheme::FullDomainBootstrap(const std::shared_ptr<RingGSWCryptoParams> &params,
                                                  const RingGSWEvalKey &EK,
                                                  const std::shared_ptr<const LWECiphertextImpl> &ct1,
                                                  const std::shared_ptr<LWEEncryptionScheme> &LWEscheme,
                                                  const BootstrapFunction &bootsMAP,
                                                  SKIP_STEP step) const {

        std::vector<BootstrapFunction> fct = {bootsMAP};
        return BootstrapMultipleFunctions(params, EK, ct1, LWEscheme, fct, step)[0];

    }

    std::shared_ptr<LWECiphertextImpl> RingGSWAccumulatorScheme::Bootstrap(
            const std::shared_ptr<RingGSWCryptoParams>& params, const RingGSWEvalKey &EK,
            const std::shared_ptr<const LWECiphertextImpl>& ct1, const std::shared_ptr<LWEEncryptionScheme>& LWEscheme,
            uint32_t T) const {

        auto map = []( uint32_t a) { return a; };
        BootstrapFunction fct(map, T);

        return FullDomainBootstrap(params, EK, ct1, LWEscheme, fct, NONE);
    }

    std::shared_ptr<LWECiphertextImpl> RingGSWAccumulatorScheme::HalfDomainBootstrap(
            const std::shared_ptr<RingGSWCryptoParams>& params, const RingGSWEvalKey &EK,

            const std::shared_ptr<const LWECiphertextImpl>& ct1, const std::shared_ptr<LWEEncryptionScheme>& LWEscheme,
            const BootstrapFunction& bootsMAP) {


        NativeInteger q = params->GetLWEParams()->Getq();
        NativeInteger Q = params->GetLWEParams()->GetQ();

        uint32_t n = params->GetLWEParams()->Getn();
        uint32_t N = params->GetLWEParams()->GetN();

        // induced values
        uint32_t T = bootsMAP.GetMessageSpace();
        NativeInteger delta_Qt = Q.DivideAndRound(T);

        // temporary variables
        // 0
        auto zero = lbcrypto::NativePoly(params->GetPolyParams(), EVALUATION, true);
        // used to multiply the rotation polys by X^modswitch(b, q, 2 * N)
        auto xB = lbcrypto::NativePoly(params->GetPolyParams(), COEFFICIENT, true);
        // contain modswitch(\vec{a}, q, 2 * N)
        auto aN = NativeVector(n, 2 * N);
        // accumulator
        auto accu = std::make_shared<RingGSWCiphertext>(1, 2);

        // Modulo switch
        auto &a = ct1->GetA();
        auto b = ct1->GetB();

        for(uint32_t i = 0; i < n; i++) {
            aN[i] = a[i].MultiplyAndRound(2 * N, q);
        }

        uint64_t bN = b.MultiplyAndRound(2 * N, q).ConvertToInt();
        xB[bN % N] = bN < N ? 1 : Q-1;
        xB.SetFormat(EVALUATION);

        auto rotP = constructRotationPolynomial(params, bootsMAP);

        (*accu)[0][0] = std::move(zero);
        (*accu)[0][1] = std::move(rotP.first);

        accu->SetFormat(EVALUATION);
        (*accu)[0][1] *= xB * delta_Qt;


         TIME_SECTION_MILLIS("HDB Blindrotate", auto BR_result = BlindRotate(params, EK, accu, aN));

#ifdef WITH_SECRET_KEY
        auto dec = (*BR_result)[0][1] - (*BR_result)[0][0] * EK.RingPoly;
        dec.SetFormat(COEFFICIENT);
        std::cerr << dec << std::endl;
#endif

        // extract LWE sample
        auto NTT_A = (*BR_result)[0][0].Transpose();
        auto NTT_B = (*BR_result)[0][1].Transpose();

        NTT_A.SetFormat(COEFFICIENT);
        NTT_B.SetFormat(COEFFICIENT);

        // back to the orginal ct space
        auto lwe_QN = std::make_shared<LWECiphertextImpl>(NTT_A.GetValues(), NTT_B[0]);

        {
            TIME_SECTION_MILLIS("HDB Keyswitch",  auto lwe_Q = LWEscheme->KeySwitch(params->GetLWEParams(), EK.KSkey, lwe_QN));
            auto lwe = LWEscheme->ModSwitch(params->GetLWEParams(), lwe_Q);

            return lwe;
        }
    }

    std::shared_ptr<LWECiphertextImpl>
    RingGSWAccumulatorScheme::Finalize(const std::shared_ptr<RingGSWCryptoParams> &params, const RingGSWEvalKey &EK,
                                       std::shared_ptr<LWEEncryptionScheme> &scheme,
                                       std::shared_ptr<const LWECiphertextImpl> ct,
                                       SKIP_STEP from) {

        if (from == KEYSWITCH) {
            auto lwe_Q = scheme->KeySwitch(params->GetLWEParams(), EK.KSkey, ct);
            return scheme->ModSwitch(params->GetLWEParams(), lwe_Q);
        } else if (from == MODSWITCH)
            return scheme->ModSwitch(params->GetLWEParams(), ct);
        else {
            // People make mistakes, so getting here can happen
            return std::make_shared<LWECiphertextImpl>(ct->GetA(), ct->GetB());
        }
    }



    std::shared_ptr<LWECiphertextImpl>
    RingGSWAccumulatorScheme::BootstrapBinary(const shared_ptr<RingGSWCryptoParams> &params, const RingGSWEvalKey &EK,
                                              const shared_ptr<const LWECiphertextImpl> &ct1,
                                              const std::shared_ptr<LWEEncryptionScheme>& lwescheme) {

        NativeInteger q = params->GetLWEParams()->Getq();
        NativeInteger Q = params->GetLWEParams()->GetQ();
        auto polyParams = params->GetPolyParams();
        uint32_t n = params->GetLWEParams()->Getn();
        uint32_t N = params->GetLWEParams()->GetN();
        NativeInteger Q8 = Q / NativeInteger(8) + 1;

        NativeVector a(n, q);
        NativeInteger b;

        a = ct1->GetA();
        b = ct1->GetB().ModAddFast(q >> 2, q);

        //\\

        // Specifies the range [q1,q2) that will be used for mapping
        uint32_t qHalf = q.ConvertToInt() >> 1;
        NativeInteger q1 = NativeInteger(7) * (q >> 3);
        NativeInteger q2 = q1.ModAddFast(NativeInteger(qHalf), q);

        // depending on whether the value is the range, it will be set
        // to either Q/8 or -Q/8 to match binary arithmetic
        NativeInteger Q8Neg = Q - Q8;

        NativeVector m(params->GetLWEParams()->GetN(),
                       params->GetLWEParams()->GetQ());
        // Since q | (2*N), we deal with a sparse embedding of Z_Q[x]/(X^{q/2}+1) to
        // Z_Q[x]/(X^N+1)
        uint32_t factor = (2 * N / q.ConvertToInt());

        for (uint32_t j = 0; j < qHalf; j++) {
            NativeInteger temp = b.ModSub(j, q);
            if (q1 < q2)
                m[j * factor] = ((temp >= q1) && (temp < q2)) ? Q8Neg : Q8;
            else
                m[j * factor] = ((temp >= q2) && (temp < q1)) ? Q8 : Q8Neg;
        }
        std::vector<lbcrypto::NativePoly> res(2);
        // no need to do NTT as all coefficients of this poly are zero
        res[0] = lbcrypto::NativePoly(polyParams, Format::EVALUATION, true);
        res[1] = lbcrypto::NativePoly(polyParams, Format::COEFFICIENT, false);
        res[1].SetValues(std::move(m), Format::COEFFICIENT);
        res[1].SetFormat(Format::EVALUATION);

        // main accumulation computation
        // the following loop is the bottleneck of bootstrapping/binary gate
        // evaluation
        auto acc = std::make_shared<RingGSWCiphertext>(1, 2);
        (*acc)[0] = std::move(res);
        BlindRotate(params, EK, acc, a);

        //
        NativeInteger bNew;
        NativeVector aNew(N, Q);

        // the accumulator result is encrypted w.r.t. the transposed secret key
        // we can transpose "a" to get an encryption under the original secret key
        lbcrypto::NativePoly temp = (*acc)[0][0];
        temp = temp.Transpose();
        temp.SetFormat(Format::COEFFICIENT);
        aNew = temp.GetValues();

        temp = (*acc)[0][1];
        temp.SetFormat(Format::COEFFICIENT);
        // we add Q/8 to "b" to to map back to Q/4 (i.e., mod 2) arithmetic.
        bNew = Q8.ModAddFast(temp[0], Q);

        auto eQN = std::make_shared<LWECiphertextImpl>(std::move(aNew), std::move(bNew));

        // Key switching
        const std::shared_ptr<const LWECiphertextImpl> eQ =
                lwescheme->KeySwitch(params->GetLWEParams(), EK.KSkey, eQN);

        // Modulus switching
        return lwescheme->ModSwitch(params->GetLWEParams(), eQ);
    }
}