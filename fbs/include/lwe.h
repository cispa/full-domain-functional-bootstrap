// ORIGINAL PALISADE NOTICE

// @file lwe.h - LWE Encryption Scheme as described in
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

// MODIFICATIONS DONE FOR FDFB
// - CIPHERTEXT STATE
// - MODIFIED ENCRYPT/DECRYPT
// - MODIFIED KEYGEN/KEYGENN
// - ENCODE/DECODE

#ifndef FBSFHE_LWE_H
#define FBSFHE_LWE_H

// undefine to output the noise value during decryption
// #define BINFHE_DEBUG

#include <memory>

#include "lwecore.h"

namespace fbscrypto {

    /*
     * What kind of ciphertext to output when decrypting
     */
    enum CIPHERTEXT_STATE {
        FRESH,
        TRIVIAL,
        NOISELESS,
        BEFORE_KEYSWITCH,
        TRIVIAL_BEFORE_KEYSWITCH,
        NOISELESS_BEFORE_KEYSWITCH,
        BEFORE_MODSWITCH,
        TRIVIAL_BEFORE_MODSWITCH,
        NOISELESS_BEFORE_MODSWITCH
    };

/**
 * @brief Additive LWE scheme
 */
class LWEEncryptionScheme {
 public:
  LWEEncryptionScheme() {}

  /**
   * Generates a secret key of dimension n using modulus q
   *
   * @param params a shared pointer to LWE scheme parameters
   * @return a shared pointer to the secret key
   */
  std::shared_ptr<LWEPrivateKeyImpl> KeyGen(
      std::shared_ptr<LWECryptoParams> params) const;

  /**
   * Generates a secret key of dimension N using modulus Q
   *
   * @param params a shared pointer to LWE scheme parameters
   * @return a shared pointer to the secret key
   */
  std::shared_ptr<LWEPrivateKeyImpl> KeyGenN(
      std::shared_ptr<LWECryptoParams> params) const;

  /**
   * Encrypts a value using a secret key (symmetric key encryption)
   *
   * @param params a shared pointer to LWE scheme parameters
   * @param sk - the secret key
   * @param &m - the plaintext
   * @return a shared pointer to the ciphertext
   */
  std::shared_ptr<LWECiphertextImpl> Encrypt(const std::shared_ptr<LWECryptoParams> &params,
                                             const std::shared_ptr<const LWEPrivateKeyImpl> &sk,
                                             const LWEPlaintext &m, CIPHERTEXT_STATE state) const;

/**
 * Encrypts a value without a secret key, by setting (a = 0, b = m)
 * @param params a shared pointer to LWE scheme parameters
 * @param &m - the plaintext
 * @return a shared pointer to the ciphertext
 */
    std::shared_ptr<LWECiphertextImpl>
    EncryptNoiseless(const std::shared_ptr<LWECryptoParams> &params, const LWEPlaintext &m, bool prekeyswitch);

  /**
   * Decrypts the ciphertext using secret key sk
   * @param params a shared pointer to LWE scheme parameters
   * @param sk the secret key
   * @param ct the ciphertext
   * @param *result plaintext result
   */
  void Decrypt(const std::shared_ptr<LWECryptoParams>& params,
               const std::shared_ptr<const LWEPrivateKeyImpl>& sk,
               const std::shared_ptr<const LWECiphertextImpl>& ct,
               LWEPlaintext* result) const;

  /**
   * Changes an LWE ciphertext modulo Q into an LWE ciphertext modulo q
   *
   * @param params a shared pointer to LWE scheme parameters
   * @param ctQ the input ciphertext
   * @return resulting ciphertext
   */
  std::shared_ptr<LWECiphertextImpl> ModSwitch(
      const std::shared_ptr<LWECryptoParams>& params,
      const std::shared_ptr<const LWECiphertextImpl>& ctQ) const;

  /**
   * Generates a switching key to go from a secret key with (Q,N) to a secret
   * key with (Q,n).
   *
   * !! Note that unlike in the GINX/FHEW implementation each digit of the KSK is precomputed,
   * !! i.e. one has an N x lKSK x LKSK matrix.
   * !! Due to space constraints, we cannot do this so we only compute the usual digit powers
   *
   * @param params a shared pointer to LWE scheme parameters
   * @param sk new secret key
   * @param skN old secret key
   * @return a shared pointer to the switching key
   */
  std::shared_ptr<LWESwitchingKey> KeySwitchGen(
      std::shared_ptr<LWECryptoParams> params,
      std::shared_ptr<const LWEPrivateKeyImpl> sk,
      std::shared_ptr<const LWEPrivateKeyImpl> skN) const;

  /**
   * Switches ciphertext from (Q,N) to (Q,n)
   *
   * @param params a shared pointer to LWE scheme parameters
   * @param K switching key
   * @param ctQN input ciphertext
   * @return a shared pointer to the resulting ciphertext
   */
  std::shared_ptr<LWECiphertextImpl> KeySwitch(
      const std::shared_ptr<LWECryptoParams> params,
      const std::shared_ptr<LWESwitchingKey> K,
      const std::shared_ptr<const LWECiphertextImpl> ctQN) const;
};

}  // namespace fbscrypto

#endif
