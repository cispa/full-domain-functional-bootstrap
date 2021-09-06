// ORIGINAL PALISADE NOTICE

// @file fhew.h - FHEW scheme header file
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

// MODIFICATIONS DONE FOR FDFB
// - SKIP_STEP
// - FULLDOMAINBOOSTRAP
// - FINALIZE
// - RLWEKEYSWITCHGEN
// - RLWEKEYSWITCH
// - BUILDACC
// - COMPUTEPOWERSOFSIG
// - BOOTSTRAPMULTIPLEFUNCTIONS
// - BOOTSTRAPINNER

#ifndef FBS_FHEW_H
#define FBS_FHEW_H

#include "lwe.h"
#include "ringcore.h"
#include "definitions.h"
#include "ringswitching.h"

namespace fbscrypto {

    enum SKIP_STEP {
        NONE,
        KEYSWITCH,
        MODSWITCH
    };

/**
 * @brief Ring GSW accumulator schemes described in
 * https://eprint.iacr.org/2014/816 and "Bootstrapping in FHEW-like
 * Cryptosystems"
 */
class RingGSWAccumulatorScheme {
 public:
  RingGSWAccumulatorScheme() {}

  /**
   * Generates a refreshing key
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param lwescheme a shared pointer to additive LWE scheme
   * @param LWEsk a shared pointer to the secret key of the underlying additive
   * LWE scheme
   * @return a shared pointer to the refreshing key
   */
  RingGSWEvalKey KeyGen(
      std::shared_ptr<RingGSWCryptoParams> params,
      std::shared_ptr<LWEEncryptionScheme> lwescheme,
      std::shared_ptr<const LWEPrivateKeyImpl> LWEsk) const;

  /*
   *  Documentation for these methods match the ones in \fbscontext.h
   *
   */
  std::shared_ptr<LWECiphertextImpl>
  Bootstrap(const std::shared_ptr<RingGSWCryptoParams>& params, const RingGSWEvalKey &EK,
            const std::shared_ptr<const LWECiphertextImpl>& ct1, const std::shared_ptr<LWEEncryptionScheme>& LWEscheme,
            uint32_t T) const;

  std::shared_ptr<LWECiphertextImpl>
  BootstrapBinary(const std::shared_ptr<RingGSWCryptoParams>& params, const RingGSWEvalKey& EK, const std::shared_ptr<const LWECiphertextImpl>& ct1, const std::shared_ptr<LWEEncryptionScheme>& LWEScheme);

  std::shared_ptr<LWECiphertextImpl>
  FullDomainBootstrap(const std::shared_ptr<RingGSWCryptoParams> &params, const RingGSWEvalKey &EK,
                      const std::shared_ptr<const LWECiphertextImpl> &ct1,
                      const std::shared_ptr<LWEEncryptionScheme> &LWEscheme, const BootstrapFunction &bootsMAP,
                      SKIP_STEP step = NONE) const;

  std::shared_ptr<LWECiphertextImpl>
  Finalize(const std::shared_ptr<RingGSWCryptoParams> &params, const RingGSWEvalKey &EK,
           std::shared_ptr<LWEEncryptionScheme> &scheme, std::shared_ptr<const LWECiphertextImpl> ct,
           SKIP_STEP from);

    static std::shared_ptr<LWECiphertextImpl> HalfDomainBootstrap(
            const std::shared_ptr<RingGSWCryptoParams>& params,
            const RingGSWEvalKey &EK,
            const std::shared_ptr<const LWECiphertextImpl>& ct1,
            const std::shared_ptr<LWEEncryptionScheme>& LWEscheme,
            const BootstrapFunction& bootsMAP
    ) ;

    /**
     * Performs a LWE to RLWE keyswitch
     * @param params Ring parameters
     * @param K RLWESwitchKey
     * @param ctQN LWE ciphertext to be switched
     * @return RLWE(m) on input LWE(m)
     */
    std::shared_ptr<RingGSWCiphertext> RLWEKeySwitch(
            const std::shared_ptr<RingGSWCryptoParams>& params,
            const std::shared_ptr<RLWESwitchingKey>& K,
            const std::shared_ptr<const LWECiphertextImpl>& ctQN
    ) const;

 private:
  /**
   * Generates a refreshing key - GINX variant
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param lwescheme a shared pointer to additive LWE scheme
   * @param LWEsk a shared pointer to the secret key of the underlying additive
   * LWE scheme
   * @return a shared pointer to the refreshing key
   */
  RingGSWEvalKey KeyGenGINX(
      std::shared_ptr<RingGSWCryptoParams> params,
      std::shared_ptr<LWEEncryptionScheme> lwescheme,
      std::shared_ptr<const LWEPrivateKeyImpl> LWEsk) const;

    /**
     * Internal RingGSW encryption used in generating the refreshing key - GINX
     * variant
     *
     * @param params a shared pointer to RingGSW scheme parameters
     * @param skFFT secret key polynomial in the EVALUATION representation
     * @param m plaintext (corresponds to a lookup entry for the LWE scheme secret
     * key)
     * @return a shared pointer to the resulting ciphertext
     */
  std::shared_ptr<RingGSWCiphertext> EncryptGINX(
      std::shared_ptr<RingGSWCryptoParams> params,
      const lbcrypto::NativePoly &skFFT, const LWEPlaintext &m) const;

  /**
   * Generates a LWE to RLWE keyswitching key under the same key coefficients
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param skN (ring) secret key
   */
  std::shared_ptr<RLWESwitchingKey> RLWEKeyswitchGen(std::shared_ptr<RingGSWCryptoParams> params,
                                                     std::shared_ptr<const LWEPrivateKeyImpl> skN) const;

  /**
   * Constructs the accumulator used in the full domain bootstrap
   *
   * @param params a shared pointer to RingGSW scheme parameters
   * @param EK a reference to the evaluation key, containing the GINX refresh key,
               a LWE to LWE switch key and a LWE to RLWE switch key
   * @param powers_of_sig a vector of LWE samples containing \Delta_{Q,t} times the powers of L_boot
   * @param rotP0 a rotation polynomial for positive domain, i.e. m \in [0, \frac{q}{2})
   * @param rotP1 a rotation polynomial for negative domain, i.e. m \in [\frac{q}{2}, q)
   * @param fct a function which is computed while bootstrapping -- used here to retrieve the message space
   * @return RLWE(rotP0 if m \in [0, \frac{q}{2}) else rotP1)
   */
  std::shared_ptr<RingGSWCiphertext> BuildAcc(
          const std::shared_ptr<RingGSWCryptoParams>& params,
          const RingGSWEvalKey& EK,
          std::vector<std::shared_ptr<LWECiphertextImpl>>& powers_of_sig,
          lbcrypto::NativePoly& rotP0, lbcrypto::NativePoly& rotP1,
          BootstrapFunction& fct
  ) const;

  /**
   * Main bootstrapping routine for full domain bootstrapping
   * @param params a shared pointer to RingGSW scheme parameters
   * @param EK a reference to the evaluation key, containing the GINX refresh key,
               a LWE to LWE switch key and a LWE to RLWE switch key
   * @param ct1 a ciphertext to be bootstrapped
   * @param LWEscheme a shared pointer to the underlying LWE scheme
   * @param functions a vector of functions to be computed during the bootstrapping phase -- assumed to work on the same message space
   * @return a vector of LWE samples, one for each function which was computed
   */
  std::vector<std::shared_ptr<LWECiphertextImpl>>
  BootstrapMultipleFunctions(const std::shared_ptr<RingGSWCryptoParams> &params, const RingGSWEvalKey &EK,
                             const std::shared_ptr<const LWECiphertextImpl> &ct1,
                             const std::shared_ptr<LWEEncryptionScheme> &LWEscheme,
                             std::vector<BootstrapFunction> &functions, SKIP_STEP step) const;

    std::vector<std::shared_ptr<LWECiphertextImpl>>
    ComputePowersOfSig(const shared_ptr<RingGSWCryptoParams> &params, const RingGSWEvalKey &EK,
                       lbcrypto::PolyImpl<NativeVector> &sgnP, const NativeVector64 &aN,
                       const NativeInteger &delta_Qt2) const;

    shared_ptr<LWECiphertextImpl>
    BootstrapInner(const std::shared_ptr<RingGSWCryptoParams> &params, const RingGSWEvalKey &EK,
                   const shared_ptr<LWEEncryptionScheme> &LWEscheme, const NativeVector64 &aN,
                   std::shared_ptr<RingGSWCiphertext> &accumulator, SKIP_STEP step) const;
};

}  // namespace fbscrypto

#endif
