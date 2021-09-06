//
// Created by leonard on 06.05.21.
//

#include "ringswitching.h"
#include "fhew.h"

namespace fbscrypto {

    std::shared_ptr<RLWESwitchingKey> RingGSWAccumulatorScheme::RLWEKeyswitchGen(
            const std::shared_ptr<RingGSWCryptoParams> params,
            const std::shared_ptr<const LWEPrivateKeyImpl> skN) const {

        uint32_t N = params->GetLWEParams()->GetN();
        NativeInteger Q = params->GetLWEParams()->GetQ();
        NativeInteger mu = Q.ComputeMu();

        auto skPoly = lbcrypto::NativePoly (params->GetPolyParams(), COEFFICIENT);
        skPoly.SetValues(skN->GetElement(), COEFFICIENT);

        skPoly.SetFormat(EVALUATION);

        auto expPK = params->GetDigitsPK();

        lbcrypto::DiscreteUniformGeneratorImpl<NativeVector> dug;
        dug.SetModulus(Q);

        std::vector<std::vector<std::shared_ptr<RingGSWCiphertext>>> resultVec(N);
        for(uint32_t i = 0; i < N; i++) {
            std::vector<std::shared_ptr<RingGSWCiphertext>> vector1(expPK);

            auto ski = skN->GetElement()[i];

            for(uint32_t j = 0; j < expPK; j++) {

                auto result = std::make_shared<RingGSWCiphertext>(1, 2);
                (*result)[0][0] = lbcrypto::NativePoly(dug, params->GetPolyParams(), EVALUATION);
#ifdef WITH_NOISE
                (*result)[0][1] = lbcrypto::NativePoly(params->GetLWEParams()->GetDgg(), params->GetPolyParams(), COEFFICIENT);
#else
                (*result)[0][1] = lbcrypto::NativePoly(params->GetPolyParams(), COEFFICIENT, true);
#endif
                (*result)[0][1][0].ModAddEq(ski.ModMulFast(params->GetPKPower()[j], Q, mu), Q);

                (*result)[0][1].SetFormat(EVALUATION);
                (*result)[0][1] += (*result)[0][0] * skPoly;

                vector1[j] = result;
            }

            resultVec[i] = std::move(vector1);
        }

        return std::make_shared<RLWESwitchingKey>(resultVec);
    }

    std::shared_ptr<RingGSWCiphertext> RingGSWAccumulatorScheme::RLWEKeySwitch(
            const std::shared_ptr<RingGSWCryptoParams>& params, const std::shared_ptr<RLWESwitchingKey>& K,
            const std::shared_ptr<const LWECiphertextImpl>& ctQN) const{

        auto result = std::make_shared<RingGSWCiphertext>(1, 2);

        (*result)[0][0] = lbcrypto::NativePoly(params->GetPolyParams(), EVALUATION, true);
        (*result)[0][1] = lbcrypto::NativePoly(params->GetPolyParams(), COEFFICIENT, true);
        (*result)[0][1][0] = ctQN->GetB();
        (*result)[0][1].SetFormat(EVALUATION);

        uint32_t basePK = params->GetBasePK();
        uint32_t expPK = params->GetDigitsPK();
        uint32_t N = params->GetLWEParams()->GetN();
        auto& key = (*K).GetElements();

        for(uint32_t i = 0; i < N; i++) {
            auto atmp = ctQN->GetA(i).ConvertToInt();
            for(uint32_t j = 0; j < expPK; j++, atmp /= basePK) {
                auto a0 = atmp % basePK;
                auto& sample = key[i][j];

                if (a0 > 0) {
                    (*result)[0][0] -= a0 * (*sample)[0][0];
                    (*result)[0][1] -= a0 * (*sample)[0][1];
                }
            }
        }

        return result;
    }
}