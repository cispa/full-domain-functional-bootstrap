// ORIGINAL PALISADE NOTICE

// @file lwecore.h - Main Classes for Boolean circuit FHE.
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
// - FBSKEYTYPE
// - MODIFIED LWECryptoParams
// - MODIFIED LweCiphertextImpl

#ifndef FBS_LWECORE_H
#define FBS_LWECORE_H

#include <string>
#include <utility>
#include <vector>

#include "math/backend.h"
#include "math/discretegaussiangenerator.h"
#include "utils/serializable.h"

namespace fbscrypto {

    enum FBSKEYTYPE {
        BINARY,
        TERNARY,
        UNIFORM
    };

typedef int64_t LWEPlaintext;

/**
 * @brief Class that stores all parameters for the LWE scheme
 */
class LWECryptoParams {
 public:
  LWECryptoParams() : m_n(0), m_N(0), m_q(0), m_Q(0), m_HM(0), m_baseKS(0), lwe_type(BINARY), rlwe_type(UNIFORM) {}

  /**
   * Main constructor for LWECryptoParams
   *
   * @param n lattice parameter for additive LWE scheme
   * @param N ring dimension for RingGSW/RLWE used in bootstrapping
   * @param &q modulus for additive LWE
   * @param &Q modulus for RingGSW/RLWE used in bootstrapping
   * @param std standard deviation
   * @param baseKS the base used for key switching
   */
  explicit LWECryptoParams(uint32_t n, uint32_t N, const NativeInteger &q, const NativeInteger &Q, double std,
                           uint32_t ksk_dgg_exp, uint32_t HM, uint32_t baseKS, FBSKEYTYPE lweKeyType,
                           FBSKEYTYPE rlweKeyType)
      : m_n(n), m_N(N), m_q(q), m_Q(Q), m_HM(HM), m_baseKS(baseKS), lwe_type(lweKeyType), rlwe_type(rlweKeyType) {
    m_dgg.SetStd(std);
    m_KSKdgg.SetStd(std::pow(2, ksk_dgg_exp));

    PreCompute();
  }

  /**
   * Performs precomputations based on the supplied parameters
   */
  void PreCompute() {
    // Number of digits in representing numbers mod Q
    uint32_t digitCount = (uint32_t)std::ceil(
        log(m_Q.ConvertToDouble()) / log(static_cast<double>(m_baseKS)));
    // Populate digits
    NativeInteger value = 1;
    for (uint32_t i = 0; i < digitCount; i++) {
      m_digitsKS.push_back(value);
      value *= m_baseKS;
    }
  }

  explicit LWECryptoParams(const LWECryptoParams &rhs) {
    this->m_n = rhs.m_n;
    this->m_N = rhs.m_N;
    this->m_q = rhs.m_q;
    this->m_Q = rhs.m_Q;
    this->m_HM = rhs.m_HM;
    this->m_baseKS = rhs.m_baseKS;
    this->m_digitsKS = rhs.m_digitsKS;
    this->m_dgg.SetStd(rhs.m_dgg.GetStd());
  }

  explicit LWECryptoParams(const LWECryptoParams &&rhs) {
    this->m_n = std::move(rhs.m_n);
    this->m_N = std::move(rhs.m_N);
    this->m_q = std::move(rhs.m_q);
    this->m_Q = std::move(rhs.m_Q);
    this->m_HM = std::move(rhs.m_HM);
    this->m_baseKS = std::move(rhs.m_baseKS);
    this->m_digitsKS = std::move(rhs.m_digitsKS);
    this->m_dgg.SetStd(rhs.m_dgg.GetStd());
  }

  const LWECryptoParams &operator=(const LWECryptoParams &rhs) {
    this->m_n = rhs.m_n;
    this->m_N = rhs.m_N;
    this->m_q = rhs.m_q;
    this->m_Q = rhs.m_Q;
    this->m_HM = rhs.m_HM;
    this->m_baseKS = rhs.m_baseKS;
    this->m_digitsKS = rhs.m_digitsKS;
    this->m_dgg.SetStd(rhs.m_dgg.GetStd());
    return *this;
  }

  const LWECryptoParams &operator=(const LWECryptoParams &&rhs) {
    this->m_n = std::move(rhs.m_n);
    this->m_N = std::move(rhs.m_N);
    this->m_q = std::move(rhs.m_q);
    this->m_Q = std::move(rhs.m_Q);
    this->m_HM = std::move(rhs.m_HM);
    this->m_baseKS = std::move(rhs.m_baseKS);
    this->m_digitsKS = std::move(rhs.m_digitsKS);
    this->m_dgg.SetStd(rhs.m_dgg.GetStd());
    return *this;
  }

  uint32_t Getn() const { return m_n; }

  uint32_t GetN() const { return m_N; }

  uint32_t GetHM() const {return m_HM; }

  FBSKEYTYPE GetLweType() const {return lwe_type; }

  FBSKEYTYPE GetRlweType() const { return rlwe_type; }

  const NativeInteger &Getq() const { return m_q; }

  const NativeInteger &GetQ() const { return m_Q; }

  uint32_t GetBaseKS() const { return m_baseKS; }

  const std::vector<NativeInteger> &GetDigitsKS() const { return m_digitsKS; }

  const lbcrypto::DiscreteGaussianGeneratorImpl<NativeVector> &GetDgg() const {
    return m_dgg;
  }

  const lbcrypto::DiscreteGaussianGeneratorImpl<NativeVector> &GetKSKDgg() const {
      return m_KSKdgg;
  }

  bool operator==(const LWECryptoParams &other) const {
    return m_n == other.m_n && m_N == other.m_N && m_q == other.m_q && m_HM == other.m_HM &&
           m_Q == other.m_Q && m_dgg.GetStd() == other.m_dgg.GetStd() &&
           m_baseKS == other.m_baseKS && m_digitsKS == other.m_digitsKS;
  }

  bool operator!=(const LWECryptoParams &other) const {
    return !(*this == other);
  }

  template <class Archive>
  void save(Archive &ar, std::uint32_t const version) const {
    ar(::cereal::make_nvp("n", m_n));
    ar(::cereal::make_nvp("N", m_N));
    ar(::cereal::make_nvp("q", m_q));
    ar(::cereal::make_nvp("Q", m_Q));
    ar(::cereal::make_nvp("HM", m_HM));
    ar(::cereal::make_nvp("sigma", m_dgg.GetStd()));
    ar(::cereal::make_nvp("bKS", m_baseKS));
  }

  template <class Archive>
  void load(Archive &ar, std::uint32_t const version) {
    if (version > SerializedVersion()) {
      PALISADE_THROW(lbcrypto::deserialize_error,
                     "serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
    }

    ar(::cereal::make_nvp("n", m_n));
    ar(::cereal::make_nvp("N", m_N));
    ar(::cereal::make_nvp("q", m_q));
    ar(::cereal::make_nvp("Q", m_Q));
    double sigma;
    ar(::cereal::make_nvp("sigma", sigma));
    this->m_dgg.SetStd(sigma);
    ar(::cereal::make_nvp("HM", m_HM));
    ar(::cereal::make_nvp("bKS", m_baseKS));

    this->PreCompute();
  }

  std::string SerializedObjectName() const { return "LWECryptoParams"; }
  static uint32_t SerializedVersion() { return 1; }

 private:
  // lattice parameter for the additive LWE scheme
  uint32_t m_n;
  // ring dimension for RingGSW/RingLWE scheme
  uint32_t m_N;
  // modulus for the additive LWE scheme
  NativeInteger m_q;
  // modulus for the RingGSW/RingLWE scheme
  NativeInteger m_Q;
  // Error distribution generator
  lbcrypto::DiscreteGaussianGeneratorImpl<NativeVector> m_dgg;
  // Error generator for Keyswitchkey
  lbcrypto::DiscreteGaussianGeneratorImpl<NativeVector> m_KSKdgg;
  // Base used in key switching
  uint32_t m_baseKS;
  // Hamming weight for secret key
  uint32_t m_HM;

  // Key type for lwe key binary/ternary/uniform
  FBSKEYTYPE lwe_type;
  // Key type ring key binary/ternary/uniform
  FBSKEYTYPE rlwe_type;

  // Powers of m_baseKS
  std::vector<NativeInteger> m_digitsKS;
};

/**
 * @brief Class that stores a LWE scheme ciphertext; composed of a vector "a"
 * and integer "b"
 */
class LWECiphertextImpl {
 public:
  LWECiphertextImpl() {}

  explicit LWECiphertextImpl(const NativeVector &&a, const NativeInteger &b)
      : m_a(std::move(a)), m_b(b) {}

  explicit LWECiphertextImpl(const NativeVector &a, const NativeInteger &b)
      : m_a(a), m_b(b) {}

  LWECiphertextImpl(NativeVector &&a, NativeInteger b)
      : m_a(std::move(a)), m_b(b) {}

  LWECiphertextImpl(const LWECiphertextImpl& rhs) {
      this->m_a = rhs.m_a;
      this->m_b = rhs.m_b;
  }

  /*
  explicit LWECiphertextImpl(const LWECiphertextImpl &rhs) {
    this->m_a = rhs.m_a;
    this->m_b = rhs.m_b;
  } */

  explicit LWECiphertextImpl(const LWECiphertextImpl &&rhs) {
    this->m_a = std::move(rhs.m_a);
    this->m_b = std::move(rhs.m_b);
  }

  const LWECiphertextImpl &operator=(const LWECiphertextImpl &rhs) {
    this->m_a = rhs.m_a;
    this->m_b = rhs.m_b;
    return *this;
  }

  const LWECiphertextImpl &operator=(const LWECiphertextImpl &&rhs) {
    this->m_a = std::move(rhs.m_a);
    this->m_b = std::move(rhs.m_b);
    return *this;
  }

  LWECiphertextImpl& operator+=(const LWECiphertextImpl& rhs) {

      //std::cout << m_a.GetLength() << " " << rhs.m_a.GetLength() << " " << m_a.GetModulus() << m_a.GetModulus() << " " << rhs.m_a.GetModulus() << std::endl;

      m_a += rhs.m_a;
      m_b.ModAddFastEq(rhs.m_b, m_a.GetModulus());

      return *this;
  }

  LWECiphertextImpl& operator-=(const LWECiphertextImpl& rhs) {
    m_a -= rhs.m_a;
    m_b.ModSubFastEq(rhs.m_b, m_a.GetModulus());

      return *this;
  }

  LWECiphertextImpl& operator*=(int64_t scale) {
      auto abs = std::abs(scale);
      m_a *= abs;
      m_b.ModMulEq(abs, m_a.GetModulus());

      if (scale < 0) {
          m_a = -m_a;
          if (m_b > 0) {
              m_b = m_a.GetModulus() - m_b;
          }
      }

      return *this;
  }

  friend LWECiphertextImpl operator+(LWECiphertextImpl lhs, const LWECiphertextImpl& rhs) {
      lhs += rhs;
      return lhs;
  }

  friend LWECiphertextImpl operator-(LWECiphertextImpl lhs, const LWECiphertextImpl& rhs) {
      lhs -= rhs;
      return lhs;
  }

  friend LWECiphertextImpl operator*(LWECiphertextImpl lhs, int64_t scale) {
      lhs *= scale;
      return lhs;
  }

  const NativeVector &GetA() const { return m_a; }

  const NativeInteger &GetA(std::size_t i) const { return m_a[i]; }

  const NativeInteger &GetB() const { return m_b; }

  void SetA(const NativeVector &a) { m_a = a; }

  void SetB(const NativeInteger &b) { m_b = b; }

  bool operator==(const LWECiphertextImpl &other) const {
    return m_a == other.m_a && m_b == other.m_b;
  }

  bool operator!=(const LWECiphertextImpl &other) const {
    return !(*this == other);
  }

  template <class Archive>
  void save(Archive &ar, std::uint32_t const version) const {
    ar(::cereal::make_nvp("a", m_a));
    ar(::cereal::make_nvp("b", m_b));
  }

  template <class Archive>
  void load(Archive &ar, std::uint32_t const version) {
    if (version > SerializedVersion()) {
      PALISADE_THROW(lbcrypto::deserialize_error,
                     "serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
    }

    ar(::cereal::make_nvp("a", m_a));
    ar(::cereal::make_nvp("b", m_b));
  }

  std::string SerializedObjectName() const { return "LWECiphertext"; }
  static uint32_t SerializedVersion() { return 1; }

 private:
  NativeVector m_a;
  NativeInteger m_b;
};

/**
 * @brief Class that stores the LWE scheme secret key; contains a vector
 */
class LWEPrivateKeyImpl {
 public:
  LWEPrivateKeyImpl() {}

  explicit LWEPrivateKeyImpl(const NativeVector &s) : m_s(s) {}

  explicit LWEPrivateKeyImpl(const LWEPrivateKeyImpl &rhs) {
    this->m_s = rhs.m_s;
  }

  explicit LWEPrivateKeyImpl(const LWEPrivateKeyImpl &&rhs) {
    this->m_s = std::move(rhs.m_s);
  }

  const LWEPrivateKeyImpl &operator=(const LWEPrivateKeyImpl &rhs) {
    this->m_s = rhs.m_s;
    return *this;
  }

  const LWEPrivateKeyImpl &operator=(const LWEPrivateKeyImpl &&rhs) {
    this->m_s = std::move(rhs.m_s);
    return *this;
  }

  const NativeVector &GetElement() const { return m_s; }

  void SetElement(const NativeVector &s) { m_s = s; }

  bool operator==(const LWEPrivateKeyImpl &other) const {
    return m_s == other.m_s;
  }

  bool operator!=(const LWEPrivateKeyImpl &other) const {
    return !(*this == other);
  }

  template <class Archive>
  void save(Archive &ar, std::uint32_t const version) const {
    ar(::cereal::make_nvp("s", m_s));
  }

  template <class Archive>
  void load(Archive &ar, std::uint32_t const version) {
    if (version > SerializedVersion()) {
      PALISADE_THROW(lbcrypto::deserialize_error,
                     "serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
    }

    ar(::cereal::make_nvp("s", m_s));
  }

  std::string SerializedObjectName() const { return "LWEPrivateKey"; }
  static uint32_t SerializedVersion() { return 1; }

 private:
  NativeVector m_s;
};

/**
 * @brief Class that stores the LWE scheme switching key
 */
class LWESwitchingKey {
 public:
  LWESwitchingKey() {}

  explicit LWESwitchingKey(
      const std::vector<std::vector<LWECiphertextImpl>> &key)
      : m_key(key) {}

  explicit LWESwitchingKey(const LWESwitchingKey &rhs) {
    this->m_key = rhs.m_key;
  }

  explicit LWESwitchingKey(const LWESwitchingKey &&rhs) {
    this->m_key = std::move(rhs.m_key);
  }

  const LWESwitchingKey &operator=(const LWESwitchingKey &rhs) {
    this->m_key = rhs.m_key;
    return *this;
  }

  const LWESwitchingKey &operator=(const LWESwitchingKey &&rhs) {
    this->m_key = std::move(rhs.m_key);
    return *this;
  }

  const std::vector<std::vector<LWECiphertextImpl>> &GetElements()
      const {
    return m_key;
  }

  void SetElements(
      const std::vector<std::vector<LWECiphertextImpl>> &key) {
    m_key = key;
  }

  bool operator==(const LWESwitchingKey &other) const {
    return m_key == other.m_key;
  }

  bool operator!=(const LWESwitchingKey &other) const {
    return !(*this == other);
  }

  template <class Archive>
  void save(Archive &ar, std::uint32_t const version) const {
    ar(::cereal::make_nvp("k", m_key));
  }

  template <class Archive>
  void load(Archive &ar, std::uint32_t const version) {
    if (version > SerializedVersion()) {
      PALISADE_THROW(lbcrypto::deserialize_error,
                     "serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
    }

    ar(::cereal::make_nvp("k", m_key));
  }

  std::string SerializedObjectName() const { return "LWEPrivateKey"; }
  static uint32_t SerializedVersion() { return 1; }

 private:
  std::vector<std::vector<LWECiphertextImpl>> m_key;
};

}  // namespace fbscrypto

#endif
