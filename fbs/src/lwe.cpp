// @file lwe.cpp - LWE Encryption Scheme implementation as described in
// https://eprint.iacr.org/2014/816 Full reference:
// @misc{cryptoeprint:2014:816,
//   author = {Leo Ducas and Daniele Micciancio},
//   title = {FHEW: Bootstrapping Homomorphic Encryption in less than a second},
//   howpublished = {Cryptology ePrint Archive, Report 2014/816},
//   year = {2014},
//   note = {\url{https://eprint.iacr.org/2014/816}},
// @author TPOC: contact@palisade-crypto.org
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

#include <fbscontext.h>
#include "lwe.h"
#include "math/binaryuniformgenerator.h"
#include "math/discreteuniformgenerator.h"
#include "math/ternaryuniformgenerator.h"

namespace fbscrypto {

std::shared_ptr<LWEPrivateKeyImpl> LWEEncryptionScheme::KeyGen(
    const std::shared_ptr<LWECryptoParams> params) const {

    NativeVector vec;
    switch (params->GetLweType()) {
        case BINARY: {
            lbcrypto::BinaryUniformGeneratorImpl<NativeVector> gen;
            vec = gen.GenerateVector(params->Getn(), params->Getq());
            break;
        }
        case TERNARY: {
            lbcrypto::TernaryUniformGeneratorImpl<NativeVector> tug;
            vec = tug.GenerateVector(params->Getn(), params->Getq());
            break;
        }
        default:
            PALISADE_THROW(lbcrypto::config_error, "Invalid Key Type !");
    }
  
  // find nonzero indices
  std::vector<uint32_t> nonzero_idx;
  for(uint32_t i = 0; i < params->Getn(); i++) {
      if (vec.at(i) != 0)
          nonzero_idx.push_back(i);
  }

  // not secure !
  auto rng = std::default_random_engine {};
  // shuffle indices
  std::shuffle(nonzero_idx.begin(), nonzero_idx.end(), rng);

  // remove necessary amount of entries to make key sparse
  int to_delete = (int)nonzero_idx.size() - (int)params->GetHM();
  nonzero_idx.resize(std::max(to_delete, 0));
    for(uint32_t i : nonzero_idx) {
        vec[i] = 0;
    }

  return std::make_shared<LWEPrivateKeyImpl>(
      LWEPrivateKeyImpl(vec));
}

std::shared_ptr<LWEPrivateKeyImpl> LWEEncryptionScheme::KeyGenN(
    const std::shared_ptr<LWECryptoParams> params) const {

    NativeVector vec;
    switch (params->GetRlweType()) {
        case BINARY: {
            lbcrypto::BinaryUniformGeneratorImpl<NativeVector> gen;
            vec = gen.GenerateVector(params->GetN(), params->GetQ());
            break;
        }
        case TERNARY: {
            lbcrypto::TernaryUniformGeneratorImpl<NativeVector> tug;
            vec = tug.GenerateVector(params->GetN(), params->GetQ());
            break;
        }
        case UNIFORM: {
            lbcrypto::DiscreteUniformGeneratorImpl<NativeVector> gen;
            gen.SetModulus(params->GetQ());
            vec = gen.GenerateVector(params->GetN());
            break;
        }
        default:
            PALISADE_THROW(lbcrypto::config_error, "Invalid Key Type !");
    }

    return std::make_shared<LWEPrivateKeyImpl>(
            LWEPrivateKeyImpl(vec));

}

std::shared_ptr<LWECiphertextImpl> LWEEncryptionScheme::Encrypt(const std::shared_ptr<LWECryptoParams> &params,
                                                                const std::shared_ptr<const LWEPrivateKeyImpl> &sk,
                                                                const LWEPlaintext &m, CIPHERTEXT_STATE state) const {

    NativeInteger q;
    uint32_t n;
    NativeInteger b = m;

    if (state == TRIVIAL or state == FRESH) {
        q = params->Getq();
        n = params->Getn();
    }
    else if (state == BEFORE_MODSWITCH or state == TRIVIAL_BEFORE_MODSWITCH or state == NOISELESS_BEFORE_MODSWITCH) {
        q = params->GetQ();
        n = params->Getn();
    } else {
        q = params->GetQ();
        n = params->GetN();
    }

    if (state == FRESH or state == BEFORE_MODSWITCH or state == BEFORE_KEYSWITCH) {
        b.ModAddFastEq(params->GetDgg().GenerateInteger(q), q);
    }

    NativeVector a(n, q);
    if (state == TRIVIAL or state == TRIVIAL_BEFORE_MODSWITCH or state == TRIVIAL_BEFORE_KEYSWITCH or state == BEFORE_KEYSWITCH
    or state == NOISELESS_BEFORE_KEYSWITCH) {
        for(uint32_t i = 0; i < n; i++)
            a[i] = 0;
        return std::make_shared<LWECiphertextImpl>(a, b);

    }

    lbcrypto::DiscreteUniformGeneratorImpl<NativeVector> dug;
    dug.SetModulus(q);
    a = dug.GenerateVector(n);

      NativeInteger mu = q.ComputeMu();

      const NativeVector &s = sk->GetElement();

      for (uint32_t i = 0; i < n; ++i) {
          NativeInteger elem = s[i] > 1 ? q - 1 : s[i];
          b += a[i].ModMulFast(elem, q, mu);
      }

      b.ModEq(q);

      return std::make_shared<LWECiphertextImpl>(LWECiphertextImpl(a, b));
}

std::shared_ptr<LWECiphertextImpl>
LWEEncryptionScheme::EncryptNoiseless(const std::shared_ptr<LWECryptoParams> &params, const LWEPlaintext &m,
                                      bool prekeyswitch) {

    NativeVector a(params->Getn(), prekeyswitch ? params->GetQ() : params->Getq());
    for(uint32_t i = 0; i < params->Getn(); i++)
        a[i] = 0;

    NativeInteger b = m;

    return std::make_shared<LWECiphertextImpl>(LWECiphertextImpl(a,b));
}

// classical LWE decryption
// m_result = Round(4/q * (b - a*s))
void LWEEncryptionScheme::Decrypt(
    const std::shared_ptr<LWECryptoParams>& params,
    const std::shared_ptr<const LWEPrivateKeyImpl>& sk,
    const std::shared_ptr<const LWECiphertextImpl>& ct,
    LWEPlaintext *result) const {
  // TODO in the future we should add a check to make sure sk parameters match
  // the ct parameters

  // Create local variables to speed up the computations
  NativeVector a = ct->GetA();
  uint32_t n = sk->GetElement().GetLength();
  NativeVector s = sk->GetElement();
  NativeInteger q = sk->GetElement().GetModulus();

  NativeInteger mu = q.ComputeMu();

  NativeInteger inner(0);
  for (uint32_t i = 0; i < n; ++i) {
    inner += a[i].ModMulFast(s[i], q, mu);
  }
  inner.ModEq(q);

  NativeInteger r = ct->GetB();

  r.ModSubFastEq(inner, q);

  *result = r.ConvertToInt();

}

// the main rounding operation used in ModSwitch (as described in Section 3 of
// https://eprint.iacr.org/2014/816) The idea is that Round(x) = 0.5 + Floor(x)
NativeInteger RoundqQ(const NativeInteger &v, const NativeInteger &q,
                      const NativeInteger &Q) {
  return NativeInteger((uint64_t)std::floor(0.5 + v.ConvertToDouble() *
                                                      q.ConvertToDouble() /
                                                      Q.ConvertToDouble()))
      .Mod(q);
}

// Modulus switching - directly applies the scale-and-round operation RoundQ
std::shared_ptr<LWECiphertextImpl> LWEEncryptionScheme::ModSwitch(
    const std::shared_ptr<LWECryptoParams>& params,
    const std::shared_ptr<const LWECiphertextImpl>& ctQ) const {
  NativeVector a(params->Getn(), params->Getq());

  uint32_t n = params->Getn();
  NativeInteger q = params->Getq();
  NativeInteger Q = params->GetQ();

  for (uint32_t i = 0; i < n; ++i) a[i] = RoundqQ(ctQ->GetA()[i], q, Q);

  NativeInteger b = RoundqQ(ctQ->GetB(), q, Q);

  return std::make_shared<LWECiphertextImpl>(LWECiphertextImpl(a, b));
}

std::shared_ptr<LWESwitchingKey> LWEEncryptionScheme::KeySwitchGen(
    const std::shared_ptr<LWECryptoParams> params,
    const std::shared_ptr<const LWEPrivateKeyImpl> sk,
    const std::shared_ptr<const LWEPrivateKeyImpl> skN) const {

    // Create local copies of main variables
  uint32_t n = params->Getn();
  uint32_t N = params->GetN();
  NativeInteger Q = params->GetQ();
  std::vector<NativeInteger> digitsKS = params->GetDigitsKS();
  uint32_t expKS = digitsKS.size();

  // newSK stores negative values using modulus q
  // we need to switch to modulus Q
  NativeVector newSK = sk->GetElement();
  newSK.SwitchModulus(Q);

  NativeVector oldSK = skN->GetElement();

  lbcrypto::DiscreteUniformGeneratorImpl<NativeVector> dug;
  dug.SetModulus(Q);

  NativeInteger mu = Q.ComputeMu();

  std::vector<std::vector<LWECiphertextImpl>> resultVec(N);
  auto dgg = params->GetKSKDgg();

#pragma omp parallel for
  for(uint32_t i = 0; i < N; ++i) {
      std::vector<LWECiphertextImpl> vector1(expKS);
      for (uint32_t j = 0; j < expKS; ++j) {
          NativeInteger b = oldSK[i].ModMul(digitsKS[j], Q);
#ifdef WITH_NOISE
          b.ModAddFastEq(dgg.GenerateInteger(Q), Q);
#endif
          NativeVector a = dug.GenerateVector(n);
          for (int k = 0; k < n; ++k) {
              b += a[k].ModMulFast(newSK[k], Q, mu);
          }
          b.ModEq(Q);

          vector1[j] = LWECiphertextImpl(a, b);
      }
      resultVec[i] = std::move(vector1);
  }

  return std::make_shared<LWESwitchingKey>(resultVec);
}

// the key switching operation as described in Section 3 of
// https://eprint.iacr.org/2014/816
std::shared_ptr<LWECiphertextImpl> LWEEncryptionScheme::KeySwitch(
    const std::shared_ptr<LWECryptoParams> params,
    const std::shared_ptr<LWESwitchingKey> K,
    const std::shared_ptr<const LWECiphertextImpl> ctQN) const {
  uint32_t n = params->Getn();
  uint32_t N = params->GetN();
  NativeInteger Q = params->GetQ();
  uint32_t baseKS = params->GetBaseKS();
  std::vector<NativeInteger> digitsKS = params->GetDigitsKS();
  uint32_t expKS = digitsKS.size();

  // creates an empty vector
  NativeVector a(n, Q);
  NativeInteger b = ctQN->GetB();
  NativeVector aOld = ctQN->GetA();

  NativeInteger mu = Q.ComputeMu();

  for (uint32_t i = 0; i < N; ++i) {
    NativeInteger atmp = aOld[i];
    for (uint32_t j = 0; j < expKS; ++j, atmp /= baseKS) {
      uint64_t a0 = (atmp % baseKS).ConvertToInt();
      auto& sample = K->GetElements()[i][j];
      auto& A = sample.GetA();
      auto& B = sample.GetB();

      for (uint32_t k = 0; k < n; ++k)
        a[k].ModSubFastEq(A[k].ModMulFast(a0, Q, mu), Q);

      b.ModSubFastEq(B.ModMulFast(a0, Q, mu), Q);
    }
  }

  return std::make_shared<LWECiphertextImpl>(LWECiphertextImpl(a, b));
}

};  // namespace fbscrypto
