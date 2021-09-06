



// ORIGINAL PALISADE NOTICE

// @file binfhecontext.h - Header file for FBSFHEContext class, which is used
// for Boolean circuit FHE schemes
//
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

// ADDED OBJECTS FOR FDFB:
// - MODIFIED ENCRYPT/DECRYPT FUNCTION
// - RENAMED BINFHECONTEXT to FDFBCONTEXT
// - FBSFHEPARAMSET
// - FBSFHEPARAMSET_LIST
// - FBSFHEPARAMSET_NAMES
// - GETSKN(POLY) METHODS
// - FULLDOMAINBOOTSTRAP
// - FINALIZE
// - HALFDOMAINBOOTSTRAP
// - ENCODE
// - DECODE
// - MODIFIED KEYGEN/KEYGENN METHODS


#ifndef FBS_BINFHECONTEXT_H
#define FBS_BINFHECONTEXT_H

#include <memory>
#include <string>

#include "definitions.h"
#include "fhew.h"
#include "lwe.h"
#include "ringcore.h"
#include "utils/serializable.h"

namespace fbscrypto {


// FDFB/TFHE parameter sets
enum FBSFHEPARAMSET {

    FDFB_80_6 = 1,
    FDFB_100_6,
    FDFB_80_7,
    FDFB_100_7,
    FDFB_80_8,
    FDFB_100_8,
    TFHE_100_7,
    TFHE_80_2,
    TFHE_100_2,
};

// Parameter set list for convenience
static FBSFHEPARAMSET FBSFHEPARAMSET_LIST[] = {
        FDFB_80_6,
        FDFB_100_6,
        FDFB_80_7,
        FDFB_100_7,
        FDFB_80_8,
        FDFB_100_8,
        TFHE_100_7,
        TFHE_80_2,
        TFHE_100_2,
};

// Parameter set STRING list for convenience
static std::string FBSFHEPARAMSET_NAMES[] = {
    "FDFB_80_6",
    "FDFB_100_6",
    "FDFB_80_7",
    "FDFB_100_7",
    "FDFB_80_8",
    "FDFB_100_8",
    "TFHE_100_7",
    "TFHE_80_2",
    "TFHE_100_2",
};

class LWECiphertextImpl;

using LWECiphertext = std::shared_ptr<LWECiphertextImpl>;

using ConstLWECiphertext = const std::shared_ptr<const LWECiphertextImpl>;

class LWEPrivateKeyImpl;

using LWEPrivateKey = std::shared_ptr<LWEPrivateKeyImpl>;

using ConstLWEPrivateKey = const std::shared_ptr<const LWEPrivateKeyImpl>;

/**
 * @brief FBSFHEContext
 *
 * The wrapper class for Boolean circuit FHE
 */
class FBSFHEContext  {

 public:
  FBSFHEContext() {}

  /**
   * Creates a crypto context using custom parameters.
   * Should be used with care (only for advanced users familiar with LWE
   * parameter selection).
   *
   * @param n lattice parameter for additive LWE scheme
   * @param N ring dimension for RingGSW/RLWE used in bootstrapping
   * @param &q modulus for additive LWE
   * @param &Q modulus for RingGSW/RLWE used in bootstrapping
   * @param std standard deviation
   * @param baseKS the base used for key switching
   * @param baseG the gadget base used in bootstrapping
   * @param baseR the base used for refreshing
   * @param method the bootstrapping method (AP or GINX)
   * @return creates the cryptocontext
   */
  void GenerateFDFHEContext(uint32_t n, uint32_t N, const NativeInteger &q, const NativeInteger &Q, double std,
                            uint32_t baseKS, uint32_t baseG, uint32_t baseBoot, uint32_t basePK, uint32_t HM,
                            FBSKEYTYPE lweKeyType, FBSKEYTYPE rlweKeyType);

  /**
   * Creates a crypto context using predefined parameters sets. Recommended for
   * most users.
   *
   * @param set the parameter set: TOY, MEDIUM, STD128, STD192, STD256
   * @param method the bootstrapping method (AP or GINX)
   * @return create the cryptocontext
   */
  void GenerateFDFHEContext(FBSFHEPARAMSET set, BINFHEMETHOD method = GINX);

  /**
   * Gets the refreshing key (used for serialization).
   *
   * @return a shared pointer to the refreshing key
   */
  std::shared_ptr<RingGSWBTKey> GetRefreshKey() const {
    return m_BTKey.BSkey;
  }

  /**
   * Gets the switching key (used for serialization).
   *
   * @return a shared pointer to the switching key
   */
  std::shared_ptr<LWESwitchingKey> GetSwitchKey() const {
    return m_BTKey.KSkey;
  }

  std::shared_ptr<RLWESwitchingKey> GetRLWESwitchKey() const {
      return m_BTKey.RLWEKey;
  }

#ifdef WITH_SECRET_KEY
  const NativeVector& GetSkN() const {
      return m_BTKey.skN;
  }

  const lbcrypto::NativePoly& GetSkNPoly() const {
      return m_BTKey.RingPoly;
  }
#endif
  /**
   * Generates a secret key for the main LWE scheme
   *
   * @return a shared pointer to the secret key
   */
  LWEPrivateKey KeyGen() const;

  /**
   * Generates a secret key used in bootstrapping
   * @return a shared pointer to the secret key
   */
  LWEPrivateKey KeyGenN() const;

  /**
   * Encrypts a bit using a secret key (symmetric key encryption)
   *
   * @param sk - the secret key
   * @param &m - the plaintext
   * @param state what kind of ciphertext to generate, Keyswitched, trivial, ...
   * @return a shared pointer to the ciphertext
   */
  LWECiphertext Encrypt(ConstLWEPrivateKey sk, const LWEPlaintext &m,
                        CIPHERTEXT_STATE state = FRESH) const;

  LWECiphertext EncryptNoiseless(const LWEPlaintext& m) const;

  /**
   * Decrypts a ciphertext using a secret key
   *
   * @param sk the secret key
   * @param ct the ciphertext
   * @param *result plaintext result
   */
  void Decrypt(ConstLWEPrivateKey sk, ConstLWECiphertext ct,
               LWEPlaintext *result) const;

    /**
     * Encodes a plaintext to be encrypted
     * @param pt message
     * @param msg_space message space
     * @return round(pt * LWE_q / msg_space)
     */
    LWEPlaintext Encode(LWEPlaintext pt, uint32_t msg_space, CIPHERTEXT_STATE from) const;

    /**
     * Decodes a plaintext that was encrypted
     * @param pt message
     * @param msg_space message space
     * @return round(pt * msg_space / LWE_q)
     */
    LWEPlaintext Decode(LWEPlaintext ct, uint32_t msg_space, CIPHERTEXT_STATE from = CIPHERTEXT_STATE::TRIVIAL) const;

  /**
   * Generates a switching key to go from a secret key with (Q,N) to a secret
   * key with (q,n)
   *
   * @param sk new secret key
   * @param skN old secret key
   * @return a shared pointer to the switching key
   */
  std::shared_ptr<LWESwitchingKey> KeySwitchGen(ConstLWEPrivateKey sk,
                                                ConstLWEPrivateKey skN) const;

  /**
   * Generates boostrapping keys
   *
   * @param sk secret key
   */
  void BTKeyGen(ConstLWEPrivateKey sk);

  /**
   * Loads bootstrapping keys in the context (typically after deserializing)
   *
   * @param key struct with the bootstrapping keys
   */
  void BTKeyLoad(const RingGSWEvalKey &key) { m_BTKey = key; }

  /**
   * Clear the bootstrapping keys in the current context
   */
  void ClearBTKeys() {
    m_BTKey.BSkey.reset();
    m_BTKey.KSkey.reset();
  }

  LWECiphertext BootstrapBinary(ConstLWECiphertext ct1) const;
  /**
   * Bootstraps a ciphertext (without peforming any operation)
   *
   * @param ct1 ciphertext to be bootstrapped
   * @return a shared pointer to the resulting ciphertext
   */
  LWECiphertext Bootstrap(ConstLWECiphertext ct1) const;

  /**
   * Performs a fulldomain bootstrap applying \bootstmap
   * @param ct1 ciphertext
   * @param bootsMap function wrapper
   * @param SKIP_STEP indicates which step of the bootstrapping should be skipped. e.g KEYSWITCHING
   * @return LWE(f(Phase(ct1)))
   */
  LWECiphertext FullDomainBootstrap(ConstLWECiphertext ct1, BootstrapFunction bootsMap, SKIP_STEP step = NONE) const;

  /**
   * Apply the final step skipped in \FullDomainBootstrap
   * @param ct1 ciphertext
   * @param from step that was skipped
   * @return MODSWITCH(ct1) if from == MODSWITCH else KEYSWITCH(MODSWITCH(ct1))
   */
  LWECiphertext Finalize(ConstLWECiphertext ct1, SKIP_STEP from);

  LWECiphertext HalfDomainBootstrap(ConstLWECiphertext ct2, BootstrapFunction bootsMap) const;

  std::shared_ptr<RingGSWCryptoParams> GetParams() const { return m_params; }

  std::shared_ptr<LWEEncryptionScheme> GetLWEScheme() const {
    return m_LWEscheme;
  }

  std::shared_ptr<RingGSWAccumulatorScheme> GetRingGSWScheme() const {
    return m_RingGSWscheme;
  }

  template <class Archive>
  void save(Archive &ar, std::uint32_t const version) const {
    ar(::cereal::make_nvp("params", m_params));
  }

  template <class Archive>
  void load(Archive &ar, std::uint32_t const version) {
    if (version > SerializedVersion()) {
      PALISADE_THROW(lbcrypto::deserialize_error,
                     "serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
    }
    ar(::cereal::make_nvp("params", m_params));
  }

  std::string SerializedObjectName() const { return "RingGSWBTKey"; }
  static uint32_t SerializedVersion() { return 1; }

        // Shared pointer to the underlying additive LWE scheme
        std::shared_ptr<LWEEncryptionScheme> m_LWEscheme;
    private:
  // Shared pointer to Ring GSW + LWE parameters
  std::shared_ptr<RingGSWCryptoParams> m_params;

        // Shared pointer to the underlying RingGSW/RLWE scheme
  std::shared_ptr<RingGSWAccumulatorScheme> m_RingGSWscheme;

  // Struct containing the bootstrapping keys
  RingGSWEvalKey m_BTKey;
};

}  // namespace fbscrypto

#endif
