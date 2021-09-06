//
// Created by leonard on 27.07.21.
//

#include "CRT.h"

namespace NN {

#include <cassert>

    CiphertextCRT::CiphertextCRT(const CiphertextCRT &other) : moduli(other.moduli) {
        for (auto& ct : other.contents) {

            NativeVector A = ct->GetA();
            NativeInteger b = ct->GetB();

            contents.push_back(std::make_shared<fbscrypto::LWECiphertextImpl>(A, b));
        }
    }

    CiphertextCRT &CiphertextCRT::operator=(CiphertextCRT &&other) noexcept {
        this->moduli = std::move(other.moduli);
        this->contents = std::move(other.contents);
        return *this;
    }

    CiphertextCRT & CiphertextCRT::operator=(const CiphertextCRT& other) {
        swap(*this, CiphertextCRT(other));

        return *this;
    }

    CiphertextCRT& CiphertextCRT::operator+=(const CiphertextCRT &other) {
        for(uint32_t i = 0; i < contents.size(); i++) {
            (*contents[i]) += (*other.contents[i]);
        }
        return *this;
    }

    CiphertextCRT& CiphertextCRT::operator-=(const CiphertextCRT &other) {
        for(uint32_t i = 0; i < contents.size(); i++) {
            (*contents[i]) -= (*other.contents[i]);
        }
        return *this;
    }

    CiphertextCRT& CiphertextCRT::operator*=(const int64_t scale) {
        for(uint32_t i = 0; i < contents.size(); i++) {
            uint32_t rem = scale % moduli[i];
            int32_t actual_scale = scale < 0 ? int32_t(rem) - int32_t(moduli[i]) : int32_t(rem);
            (*contents[i]) *= actual_scale;
        }
        return *this;
    }

    CiphertextCRT operator+(CiphertextCRT lhs, const CiphertextCRT &other) {
        lhs += other;
        return lhs;
    }

    CiphertextCRT operator-(CiphertextCRT lhs, const CiphertextCRT &other) {
        lhs -= other;
        return lhs;
    }

    CiphertextCRT operator*(CiphertextCRT lhs, const int64_t coef) {
        lhs *= coef;
        return lhs;
    }

    std::ostream& operator<<(std::ostream& stream, const CiphertextCRT& crt) {
        stream << "[ ";
        for(int i = 0; i < crt.contents.size() - 1; i++) {
            stream << 0 << ", ";
        }
        stream << 0 << " ]";

        return stream;
    }

    PlaintextCRT::PlaintextCRT(const PlaintextCRT &other) : moduli(other.moduli), contents(other.contents) {

    };

    PlaintextCRT& PlaintextCRT::operator=(PlaintextCRT &&other) {
        contents = std::move(other.contents);
        moduli = std::move(other.moduli);
        return *this;
    }

    PlaintextCRT & PlaintextCRT::operator=(const PlaintextCRT& other) {
        using std::swap;
        PlaintextCRT tmp(other);
        swap(contents, tmp.contents);
        return *this;
    }

    PlaintextCRT & PlaintextCRT::operator+=(const PlaintextCRT &other) {
        for (uint32_t i = 0; i < contents.size(); i++) {
            contents[i] = (contents[i] + other.contents[i]) % moduli[i];
        }
        return *this;
    }

    PlaintextCRT & PlaintextCRT::operator-=(const PlaintextCRT &other) {
        for (uint32_t i = 0; i < contents.size(); i++) {
            uint32_t a = contents[i];
            uint32_t b = other.contents[i];

            if (a < b)
                a += moduli[i];

            contents[i] = a - b;
        }

        return *this;
    }

    PlaintextCRT & PlaintextCRT::operator*=(const int64_t coef) {

        uint32_t w = std::abs(coef);
        for (uint32_t i = 0; i < contents.size(); i++) {
            contents[i] = (contents[i] * (w % moduli[i])) % moduli[i];
            if (coef < 0 && contents[i] > 0) {
                contents[i] = moduli[i] - contents[i];
            }
        }

        return *this;
    }

    PlaintextCRT operator+(PlaintextCRT lhs, const PlaintextCRT& other) {
        lhs += other;
        return lhs;
    }

    PlaintextCRT operator-(PlaintextCRT lhs, const PlaintextCRT& other) {
        lhs -= other;
        return lhs;
    }

    PlaintextCRT operator*(PlaintextCRT lhs, const int64_t coef) {
        lhs *= coef;
        return lhs;
    }


    std::vector<uint64_t> &PlaintextCRT::GetContents() {
        return contents;
    }

    std::ostream& operator<<(std::ostream& stream, const PlaintextCRT& crt) {
        stream << "[ ";
        for(int i = 0; i < crt.contents.size() - 1; i++) {
            stream << crt.contents[i] << ", ";
        }
        stream << crt.contents[crt.contents.size() - 1] << " ]";

        return stream;
    }

}