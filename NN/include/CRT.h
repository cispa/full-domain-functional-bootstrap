//
// Created by leonard on 27.07.21.
//

#ifndef FBS_CRT_H
#define FBS_CRT_H

#include <vector>

#include "fbscontext.h"

namespace NN {

    struct PlaintextCRT {

        PlaintextCRT() : moduli(0), contents(0) {}

        explicit PlaintextCRT(std::vector<uint64_t>& moduli) : moduli(moduli), contents(moduli.size()) {

        }

        explicit PlaintextCRT(uint64_t value, std::vector<uint64_t>& moduli) : moduli(moduli) {
            for (auto mod : moduli) {
                contents.push_back(value % mod);
            }
        };

        PlaintextCRT(std::vector<uint64_t>& values, std::vector<uint64_t>& moduli) : contents(values), moduli(moduli) {
        };

        PlaintextCRT(const PlaintextCRT& other);

        PlaintextCRT& operator=(PlaintextCRT&& other);

        PlaintextCRT& operator=(const PlaintextCRT& other);

        PlaintextCRT& operator+=(const PlaintextCRT& other);

        friend PlaintextCRT operator+(PlaintextCRT lhs, const PlaintextCRT& other);

        PlaintextCRT& operator-=(const PlaintextCRT& other);

        friend PlaintextCRT operator-(PlaintextCRT lhs, const PlaintextCRT& other);

        PlaintextCRT& operator*=(int64_t coef);

        friend PlaintextCRT operator*(PlaintextCRT lhs, int64_t coef);

        friend std::ostream& operator<<(std::ostream& out, const PlaintextCRT& crt);

        uint64_t at(uint32_t idx) const {
            return contents[idx];
        }

        std::vector<uint64_t> &GetContents();

    private:
        std::vector<uint64_t> contents;

    private:
        std::vector<uint64_t> moduli;
    };

/**
 * Chinese remainder theorem ciphertext, tuple of LWE ciphertext. Mostly a convenience class
 * LWE equivalent of PlaintextCRT
 */
    struct CiphertextCRT {

        CiphertextCRT() : contents(0), moduli(0) {};

        CiphertextCRT(std::vector<fbscrypto::LWECiphertext>& contents, std::vector<uint64_t>& moduli) : contents(contents), moduli(moduli) {};

        CiphertextCRT(const CiphertextCRT& other);

        //CiphertextCRT(const CryptoData& data, int msg, const std::vector<uint32_t>& moduli);

        CiphertextCRT& operator=(CiphertextCRT&& other) noexcept;

        CiphertextCRT& operator=(const CiphertextCRT& other);

        CiphertextCRT& operator+=(const CiphertextCRT& other);

        friend CiphertextCRT operator+(CiphertextCRT lhs, const CiphertextCRT& other);

        CiphertextCRT& operator-=(const CiphertextCRT& other);

        friend CiphertextCRT operator-(CiphertextCRT lhs, const CiphertextCRT& other);

        CiphertextCRT& operator*=(int64_t coef);

        friend CiphertextCRT operator*(CiphertextCRT lhs, int64_t coef);

        //PlaintextCRT Unpack(const CryptoData& data);

        friend std::ostream& operator<<(std::ostream& stream, const CiphertextCRT& crt);

        friend void swap(CiphertextCRT& lhs, CiphertextCRT rhs) {
            using std::swap;

            swap(lhs.contents, rhs.contents);
            swap(lhs.moduli, rhs.moduli);
        }

        const fbscrypto::LWECiphertext& at(uint32_t idx) const {
            return contents[idx];
        }

    private:
        std::vector<fbscrypto::LWECiphertext> contents;
        std::vector<uint64_t> moduli;
    };

}

#endif //FBS_CRT_H
