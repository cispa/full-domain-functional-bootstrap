// ORIGINAL PALISADE NOTICE
// MODIFICATIONS DISCUSSED in fbscontext.h

// @file binfhecontext.cpp - Implementation file for Boolean Circuit FHE context
// class
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, Duality Technologies Inc.
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "fbscontext.h"

namespace fbscrypto {

    void FBSFHEContext::GenerateFDFHEContext(uint32_t n, uint32_t N, const NativeInteger &q, const NativeInteger &Q,
                                             double std,
                                             uint32_t baseKS, uint32_t baseG, uint32_t baseBoot, uint32_t basePK,
                                             uint32_t HM,
                                             FBSKEYTYPE lweKeyType, FBSKEYTYPE rlweKeyType) {

        auto lweparams = std::make_shared<LWECryptoParams>(n, N, q, Q, std,39, HM, baseKS, lweKeyType, rlweKeyType);
        m_params =
                std::make_shared<RingGSWCryptoParams>(lweparams, baseG, baseBoot, basePK, GINX);
    }

    void FBSFHEContext::GenerateFDFHEContext(FBSFHEPARAMSET set,
                                             BINFHEMETHOD method) {
        shared_ptr<LWECryptoParams> lweparams;

        static NativeInteger Q_1 = 1152921504606748673ull;
        static NativeInteger Q_2 = 1152921504606830593ull;
        static NativeInteger Q_3 = 281474976546817ull;
        static NativeInteger Q_4 = 4294828033ull;


        switch(set) {
            case FDFB_80_6:
                lweparams = std::make_shared<LWECryptoParams>(700, 1 << 11, 1 << 12, Q_1, 3.19,38, 64, 1 << 6, BINARY, UNIFORM);
                m_params = std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 11, 1 << 11, 1 << 13, method);
                break;
            case FDFB_100_6:
                lweparams = std::make_shared<LWECryptoParams>(1050, 1 << 11, 1 << 12, Q_1, 3.19,41, 64, 1 << 1, BINARY, UNIFORM);
                m_params = std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 11, 1 << 11, 1 << 13, method);
                break;
            case FDFB_80_7:
                lweparams = std::make_shared<LWECryptoParams>(700, 1 << 12, 1 << 13, Q_2, 3.19,39, 64, 1 << 4, BINARY, UNIFORM);
                m_params = std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 9, 1 << 9, 1 << 12, method);
                break;
            case FDFB_100_7:
                lweparams = std::make_shared<LWECryptoParams>(1100, 1 << 12, 1 << 13, Q_2, 3.19,41, 64, 1 << 1, BINARY, UNIFORM);
                m_params = std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 9, 1 << 9, 1 << 13, method);
                break;
            case FDFB_80_8:
                lweparams = std::make_shared<LWECryptoParams>(700, 1 << 13, 1 << 14, Q_2, 3.19, 39,64, 1 << 4, BINARY, UNIFORM);
                m_params = std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 9, 1 << 8, 1 << 13, method);
                break;
            case FDFB_100_8:
                lweparams = std::make_shared<LWECryptoParams>(1100, 1 << 13, 1 << 14, Q_2, 3.19, 41,64, 1 << 1, BINARY, UNIFORM);
                m_params = std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 9, 1 << 8, 1 << 13, method);
                break;
            case TFHE_100_7:
                lweparams = std::make_shared<LWECryptoParams>(1500, 1 << 12, 1 << 13, Q_3, 3.19, 18, 64, 1 << 1, BINARY, UNIFORM);
                m_params = std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 16, 1 << 8, 1 << 13, method);
                break;
            case TFHE_80_2:
                lweparams = std::make_shared<LWECryptoParams>(424, 1 << 10, 1 << 11, Q_4, 3.19,16, 64, 1 << 4, BINARY, UNIFORM);
                m_params = std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 11, 1 << 12, 1 << 12, method);
                break;
            case TFHE_100_2:
                lweparams = std::make_shared<LWECryptoParams>(525, 1 << 10, 1 << 11, Q_4, 3.19,16, 64, 1 << 4, BINARY, UNIFORM);
                m_params = std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 11, 1 << 12, 1ull << 31, method);
                break;
            default:
                std::string errMsg = "ERROR: No such parameter set exists for FHEW.";
                PALISADE_THROW(lbcrypto::config_error, errMsg);
        }
    }

    LWEPrivateKey FBSFHEContext::KeyGen() const {
        return m_LWEscheme->KeyGen(m_params->GetLWEParams());
    }

    LWEPrivateKey FBSFHEContext::KeyGenN() const {
        return m_LWEscheme->KeyGenN(m_params->GetLWEParams());
    }

    LWECiphertext FBSFHEContext::Encrypt(ConstLWEPrivateKey sk,
                                         const LWEPlaintext &m,
                                         CIPHERTEXT_STATE output) const {

        return m_LWEscheme->Encrypt(m_params->GetLWEParams(), sk, m, output);

    }

    LWECiphertext FBSFHEContext::EncryptNoiseless(const LWEPlaintext &m) const {
        return m_LWEscheme->EncryptNoiseless(m_params->GetLWEParams(), m, false);
    }

    LWEPlaintext FBSFHEContext::Encode(LWEPlaintext pt, uint32_t msg_space, CIPHERTEXT_STATE from) const {
        long double q;
        int64_t QI;
        if (from == FRESH or from == TRIVIAL) {
            QI = m_params->GetLWEParams()->Getq().ConvertToInt();
            q = QI;
        }
        else {
            QI = m_params->GetLWEParams()->GetQ().ConvertToInt();
            q = QI;
        }

        return int64_t(std::round((long double)(pt) * q / (long double)(msg_space))) % QI;
    }

    LWEPlaintext FBSFHEContext::Decode(LWEPlaintext ct, uint32_t msg_space, CIPHERTEXT_STATE from) const {
        long double q;
        int64_t QI;
        if (from == FRESH or from == TRIVIAL) {
            QI = m_params->GetLWEParams()->Getq().ConvertToInt();
            q = QI;
        }
        else {
            QI = m_params->GetLWEParams()->GetQ().ConvertToInt();
            q = QI;
        }
        uint32_t d = std::round((double(ct)) * double(msg_space) / q);
        return (d) % msg_space;
    }

    void FBSFHEContext::Decrypt(ConstLWEPrivateKey sk, ConstLWECiphertext ct,
                                LWEPlaintext *result) const {
        return m_LWEscheme->Decrypt(m_params->GetLWEParams(), sk, ct, result);
    }

    std::shared_ptr<LWESwitchingKey> FBSFHEContext::KeySwitchGen(
            ConstLWEPrivateKey sk, ConstLWEPrivateKey skN) const {
        return m_LWEscheme->KeySwitchGen(m_params->GetLWEParams(), sk, skN);
    }

    void FBSFHEContext::BTKeyGen(ConstLWEPrivateKey sk) {
        m_BTKey = m_RingGSWscheme->KeyGen(m_params, m_LWEscheme, sk);
    }

    LWECiphertext FBSFHEContext::BootstrapBinary(ConstLWECiphertext ct1) const {
        return m_RingGSWscheme->BootstrapBinary(m_params, m_BTKey, ct1, m_LWEscheme);
    }

    LWECiphertext FBSFHEContext::Bootstrap(ConstLWECiphertext ct1) const {
        return m_RingGSWscheme->Bootstrap(m_params, m_BTKey, ct1, m_LWEscheme, 64);
    }

    LWECiphertext FBSFHEContext::Finalize(ConstLWECiphertext ct1, SKIP_STEP from) {
        return m_RingGSWscheme->Finalize(m_params, m_BTKey, m_LWEscheme, ct1, from);
    }

    LWECiphertext
    FBSFHEContext::FullDomainBootstrap(ConstLWECiphertext ct1, BootstrapFunction bootsMap, SKIP_STEP step) const {
        TIME_SECTION_MILLIS("FDB", auto result = m_RingGSWscheme->FullDomainBootstrap(m_params, m_BTKey, ct1,
                                                                                      m_LWEscheme, bootsMap, step);)
        return result;
    }

    LWECiphertext FBSFHEContext::HalfDomainBootstrap(ConstLWECiphertext ct2, BootstrapFunction bootsMap) const {
        TIME_SECTION_MILLIS("HDB", auto result = m_RingGSWscheme->HalfDomainBootstrap(m_params, m_BTKey, ct2, m_LWEscheme, bootsMap));
        return result;
    }
}  // namespace fbscrypto
