// ORIGINAL FILE


#ifndef FBS_RINGSWITCHING_H
#define FBS_RINGSWITCHING_H

//#include <utility>

#include "ringcore.h"
//#include "utils/serializable.h"

namespace fbscrypto {

    /**
     * Class to compute LWE to RLWE switching under the same modulus and coefficient vector dimension.
     * This is used while computing the powers of sig.
     * Pure container class, actual key generation is delegated to rhe RingGSWAccumulatorScheme
     */
    class RLWESwitchingKey {

    public:

        RLWESwitchingKey() {};

        explicit RLWESwitchingKey(std::vector<std::vector<std::shared_ptr<RingGSWCiphertext>>> key) : m_key(std::move(key)) {

        }

        explicit RLWESwitchingKey(const RLWESwitchingKey &rhs) {
            this->m_key = rhs.m_key;
        }

        explicit RLWESwitchingKey(const RLWESwitchingKey &&rhs) {
            this->m_key = std::move(rhs.m_key);
        }

        const RLWESwitchingKey &operator=(const RLWESwitchingKey &rhs) {
            this->m_key = rhs.m_key;
            return *this;
        }

        const RLWESwitchingKey &operator=(const RLWESwitchingKey &&rhs) {
            this->m_key = std::move(rhs.m_key);
            return *this;
        }

        const std::vector<std::vector<std::shared_ptr<RingGSWCiphertext>>> &GetElements()
        const {
            return m_key;
        }

        void SetElements(const std::vector<std::vector<std::shared_ptr<RingGSWCiphertext>>> &key) {
            m_key = key;
        }

        bool operator==(const RLWESwitchingKey &other) const {
            return m_key == other.m_key;
        }

        bool operator!=(const RLWESwitchingKey &other) const {
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

        std::string SerializedObjectName() const { return "RLWESwitchingKey"; }
        static uint32_t SerializedVersion() { return 1; }

    private:

        // matrix containing N x lPk RLWE samples
        std::vector<std::vector<std::shared_ptr<RingGSWCiphertext>>> m_key;

    };


}

#endif //FBS_RINGSWITCHING_H
