// ORIGINAL PALISADE NOTICE

// @file fhew.cpp - FHEW scheme (RingGSW accumulator) implementation
// The scheme is described in https://eprint.iacr.org/2014/816 and in
// Daniele Micciancio and Yuriy Polyakov, "Bootstrapping in FHEW-like
// Cryptosystems", Cryptology ePrint Archive, Report 2020/086,
// https://eprint.iacr.org/2020/086.
//
// Full reference to https://eprint.iacr.org/2014/816:
// @misc{cryptoeprint:2014:816,
//   author = {Leo Ducas and Daniele Micciancio},
//   title = {FHEW: Bootstrapping Homomorphic Encryption in less than a second},
//   howpublished = {Cryptology ePrint Archive, Report 2014/816},
//   year = {2014},
//   note = {\url{https://eprint.iacr.org/2014/816}},
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

// MODIFICATIONS FOR FDFB
// - REMOVED MOST ROUTINES THAT WERE NOT USED

#include "fhew.h"

namespace fbscrypto {

// Encryption for the GINX variant, as described in "Bootstrapping in FHEW-like
// Cryptosystems"
std::shared_ptr<RingGSWCiphertext> RingGSWAccumulatorScheme::EncryptGINX(
    const std::shared_ptr<RingGSWCryptoParams> params, const lbcrypto::NativePoly &skNTT,
    const LWEPlaintext &m) const {
  NativeInteger Q = params->GetLWEParams()->GetQ();
  uint32_t digitsG = params->GetDigitsG();
  uint32_t digitsG2 = params->GetDigitsG2();
  const shared_ptr<lbcrypto::ILNativeParams> polyParams = params->GetPolyParams();

  auto result = std::make_shared<RingGSWCiphertext>(digitsG2, 2);

  lbcrypto::DiscreteUniformGeneratorImpl<NativeVector> dug;
  dug.SetModulus(Q);

  // tempA is introduced to minimize the number of NTTs
  std::vector<lbcrypto::NativePoly> tempA(digitsG2);

  for (uint32_t i = 0; i < digitsG2; ++i) {
    (*result)[i][0] = lbcrypto::NativePoly(dug, polyParams, Format::COEFFICIENT);
    tempA[i] = (*result)[i][0];
#ifdef WITH_NOISE
    (*result)[i][1] = lbcrypto::NativePoly(params->GetLWEParams()->GetDgg(), polyParams,
                                 Format::COEFFICIENT);
#else
    (*result)[i][1] = lbcrypto::NativePoly(polyParams, COEFFICIENT, true);
#endif
  }

  for (uint32_t i = 0; i < digitsG; ++i) {
    if (m > 0) {
      // Add G Multiple
      (*result)[2 * i][0][0].ModAddEq(params->GetGPower()[i], Q);
      // [a,as+e] + G
      (*result)[2 * i + 1][1][0].ModAddEq(params->GetGPower()[i], Q);
    }
  }

  // 3*digitsG2 NTTs are called
  result->SetFormat(Format::EVALUATION);
  for (uint32_t i = 0; i < digitsG2; ++i) {
    tempA[i].SetFormat(Format::EVALUATION);
    (*result)[i][1] += tempA[i] * skNTT;
  }

  return result;
}

// wrapper for KeyGen methods
RingGSWEvalKey RingGSWAccumulatorScheme::KeyGen(
    const std::shared_ptr<RingGSWCryptoParams> params,
    const std::shared_ptr<LWEEncryptionScheme> lwescheme,
    const std::shared_ptr<const LWEPrivateKeyImpl> LWEsk) const {

    return KeyGenGINX(params, lwescheme, LWEsk);
}

// Bootstrapping keys generation for the GINX variant, as described in
// "Bootstrapping in FHEW-like Cryptosystems"
RingGSWEvalKey RingGSWAccumulatorScheme::KeyGenGINX(
    const std::shared_ptr<RingGSWCryptoParams> params,
    const std::shared_ptr<LWEEncryptionScheme> lwescheme,
    const std::shared_ptr<const LWEPrivateKeyImpl> LWEsk) const {

  RingGSWEvalKey ek;
  const std::shared_ptr<const LWEPrivateKeyImpl> skN =
      lwescheme->KeyGenN(params->GetLWEParams());

  ek.KSkey = lwescheme->KeySwitchGen(params->GetLWEParams(), LWEsk, skN);
  ek.RLWEKey = RLWEKeyswitchGen(params, skN);

  lbcrypto::NativePoly skNPoly = lbcrypto::NativePoly(params->GetPolyParams());
  skNPoly.SetValues(skN->GetElement(), Format::COEFFICIENT);


#ifdef WITH_SECRET_KEY
  ek.skN = NativeVector(skN->GetElement());
  ek.RingPoly = lbcrypto::NativePoly(params->GetPolyParams());
  ek.RingPoly.SetValues(skN->GetElement(), COEFFICIENT);
  ek.RingPoly.SetFormat(EVALUATION);
  std::cerr << "[GEN]" << LWEsk->GetElement() << std::endl;
  std::cerr << "[GEN] Private RLWE Key" << ek.skN << std::endl;
  auto copy = lbcrypto::NativePoly(ek.RingPoly);
  copy.SetFormat(COEFFICIENT);
  std::cerr << "[GEN] Private RLWE Poly " << skNPoly << std::endl;
#endif


        skNPoly.SetFormat(Format::EVALUATION);

  uint64_t q = params->GetLWEParams()->Getq().ConvertToInt();
  uint32_t n = params->GetLWEParams()->Getn();

  ek.BSkey = std::make_shared<RingGSWBTKey>(1, 2, n);

  int64_t qHalf = (q >> 1);

  // handles ternary secrets using signed mod 3 arithmetic; 0 -> {0,0}, 1 ->
  // {1,0}, -1 -> {0,1}
#pragma omp parallel for
  for (uint32_t i = 0; i < n; ++i) {
    int64_t s = LWEsk->GetElement()[i].ConvertToInt();
    if (s > qHalf) s -= q;
    switch (s) {
      case 0:
        (*ek.BSkey)[0][0][i] = *(EncryptGINX(params, skNPoly, 0));
        (*ek.BSkey)[0][1][i] = *(EncryptGINX(params, skNPoly, 0));
        break;
      case 1:
        (*ek.BSkey)[0][0][i] = *(EncryptGINX(params, skNPoly, 1));
        (*ek.BSkey)[0][1][i] = *(EncryptGINX(params, skNPoly, 0));
        break;
      case -1:
        (*ek.BSkey)[0][0][i] = *(EncryptGINX(params, skNPoly, 0));
        (*ek.BSkey)[0][1][i] = *(EncryptGINX(params, skNPoly, 1));
        break;
      default:
        std::string errMsg =
            "ERROR: only ternary secret key distributions are supported.";
        PALISADE_THROW(lbcrypto::not_implemented_error, errMsg);
    }
  }

  return ek;
}


};  // namespace fbscrypto
