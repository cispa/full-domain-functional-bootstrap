//
// Created by leonard on 27.07.21.
//

#include "Utils.h"

namespace NN {

    fbscrypto::LWECiphertext CryptoData::EncryptNormal(uint64_t value, uint64_t modulus) {
        auto encoded = ctx.Encode(value, modulus, fbscrypto::FRESH);
        return ctx.Encrypt(this->key, encoded);
    }

    CiphertextCRT CryptoData::EncryptCRT(int64_t value, fbscrypto::CIPHERTEXT_STATE from) {
        std::vector<fbscrypto::LWECiphertext> temp;

        for(unsigned long i : moduli) {
            int64_t tmp = value % int64_t(i);
            auto encoded = ctx.Encode(tmp, i, from);
            temp.push_back(ctx.Encrypt(key, encoded, from));
        }

        return {temp, this->moduli};
    }

    CiphertextCRT CryptoData::EncryptCRT(std::vector<uint64_t> &values, fbscrypto::CIPHERTEXT_STATE from) {
        std::vector<fbscrypto::LWECiphertext> temp;

        for(uint32_t i = 0; i < values.size(); i++) {

            uint64_t mod = moduli[i];
            int64_t val = values[i];

            auto encoded = ctx.Encode(val, mod, from);
            temp.push_back(ctx.Encrypt(key, encoded, from));
        }

        return {temp, this->moduli};
    }

    CiphertextCRT CryptoData::DoKeySwitch(const CiphertextCRT &crt) {
        std::vector<fbscrypto::LWECiphertext> cts;
        for(uint32_t i = 0; i < moduli.size(); i++) {
            auto& elem = crt.at(i);
            cts.push_back(ctx.Finalize(elem, fbscrypto::SKIP_STEP::KEYSWITCH));
        }

        return {cts, moduli};
    }

    CiphertextCRT CryptoData::DoModswitch(const CiphertextCRT &crt) {
        std::vector<fbscrypto::LWECiphertext> cts;
        for(uint32_t i = 0; i < moduli.size(); i++) {
            auto& elem = crt.at(i);
            cts.push_back(ctx.Finalize(elem, fbscrypto::SKIP_STEP::MODSWITCH));
        }

        return {cts, moduli};
    }

    PlaintextCRT CryptoData::DecryptCRT(const CiphertextCRT &value, fbscrypto::CIPHERTEXT_STATE from) {

        std::vector<uint64_t> values;
        int64_t pt;
        for(uint32_t i = 0; i < moduli.size(); i++) {
            auto ct = value.at(i);
            ctx.Decrypt(this->key, ct, &pt);
            values.push_back(ctx.Decode(pt, moduli[i], from));
        }

        return {values, this->moduli};
    }

    const vector<uint64_t> &CryptoData::GetModuli() const {
        return moduli;
    }

    CiphertextCRT CryptoData::BootstrapCRT(const CiphertextCRT &input, std::vector<fbscrypto::BootstrapFunction>& functions,
                                           fbscrypto::SKIP_STEP step) {

        if (moduli.size() != functions.size()) {
            throw std::invalid_argument("Number of functions does not match number of moduli/ciphertext components");
        }

        std::vector<fbscrypto::LWECiphertext> results;
        for(uint32_t i = 0; i < moduli.size(); i++) {
            results.push_back(ctx.FullDomainBootstrap(input.at(i), functions.at(i), step));
        }

        return {results, this->moduli};
    }

    void read_signed_matrix_from_csv(int64_t* buffer, uint32_t shapeX, uint32_t shapeY, std::string& path) {


        std::string line, field;
        std::ifstream iF;

        iF.open(path);
        uint32_t i = 0, j = 0;
        while (std::getline(iF, line) && (i < shapeY) ) {

            std::istringstream s(line);

            while (std::getline(s, field, ',') && (j < shapeX)) {

                int64_t value = std::stoll(field);
                buffer[i * shapeX + j] = value;

                j++;
            }
            j = 0;
            i++;
        }

        iF.close();

    }

    void read_unsigned_matrix_from_csv(uint64_t* buffer, uint32_t shapeX, uint32_t shapeY, std::string& path) {

        std::string line, field;
        std::ifstream iF;

        iF.open(path);
        uint32_t i = 0, j = 0;
        while (std::getline(iF, line) && (i < shapeY)) {

            std::istringstream s(line);

            while (std::getline(s, field, ',') && (j < shapeX)) {

                uint64_t value = std::stoull(field);
                buffer[i * shapeX + j] = value;

                j++;
            }
            j = 0;
            i++;
        }

        iF.close();

    }

    void read_signed_vector_from_csv(int64_t* buffer, uint32_t shapeY, std::string& path) {

        std::string line, field;
        std::ifstream iF;

        iF.open(path);
        uint32_t i = 0;
        while (std::getline(iF, line) && (i < shapeY)) {
            uint64_t value = std::stoll(line);
            buffer[i++] = value;
        }

        iF.close();

    }

    void read_unsigned_vector_from_csv(uint64_t* buffer, uint32_t shapeY, std::string& path) {


        std::string line, field;
        std::ifstream iF;

        iF.open(path);
        uint32_t i = 0;
        while (std::getline(iF, line) && (i < shapeY)) {
            uint64_t value = std::stoull(line);
            buffer[i++] = value;
        }

        iF.close();

    }

    long double evaluate_horner(long double input, const long double* coefs, uint64_t size) {

        if (size == 0)
            return 0.;

        auto accu = coefs[size - 1];
        for(uint32_t i = 1; i < size; i++) {
            accu = (coefs[size - i - 1] + accu * input);
        }

        return accu;
    }



}