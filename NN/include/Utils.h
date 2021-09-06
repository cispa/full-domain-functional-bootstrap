//
// Created by leonard on 27.07.21.
//

#ifndef FBS_UTILS_H
#define FBS_UTILS_H

#include "fbscontext.h"
#include "CRT.h"

namespace NN {

    class CryptoData {

    public:

        CryptoData(fbscrypto::FBSFHEPARAMSET set, std::vector<uint64_t>& moduli) : ctx(), moduli(moduli) {

            ctx.GenerateFDFHEContext(set);
            this->key = ctx.KeyGen();
            ctx.BTKeyGen(this->key);

        }

        fbscrypto::LWECiphertext EncryptNormal(uint64_t value, uint64_t modulus);

        CiphertextCRT EncryptCRT(int64_t value, fbscrypto::CIPHERTEXT_STATE from = fbscrypto::CIPHERTEXT_STATE::TRIVIAL_BEFORE_KEYSWITCH);

        CiphertextCRT DoKeySwitch(const CiphertextCRT& crt);

        CiphertextCRT DoModswitch(const CiphertextCRT& crt);

        CiphertextCRT BootstrapCRT(const CiphertextCRT& input, std::vector<fbscrypto::BootstrapFunction>& functions, fbscrypto::SKIP_STEP step = fbscrypto::SKIP_STEP::KEYSWITCH);

        CiphertextCRT EncryptCRT(std::vector<uint64_t>& values, fbscrypto::CIPHERTEXT_STATE from = fbscrypto::CIPHERTEXT_STATE::TRIVIAL_BEFORE_KEYSWITCH);

        PlaintextCRT DecryptCRT(const CiphertextCRT& value, fbscrypto::CIPHERTEXT_STATE from = fbscrypto::CIPHERTEXT_STATE::TRIVIAL_BEFORE_KEYSWITCH);

        const vector<uint64_t> &GetModuli() const;

    private:

        fbscrypto::FBSFHEContext ctx;
        fbscrypto::LWEPrivateKey key;
        std::vector<uint64_t> moduli;
    };

    // function for data input
    void read_signed_matrix_from_csv(int64_t* buffer, uint32_t shapeX, uint32_t shapeY, std::string& path);
    void read_unsigned_matrix_from_csv(uint64_t* buffer, uint32_t shapeX, uint32_t shapeY, std::string& path);
    void read_signed_vector_from_csv(int64_t* buffer, uint32_t shapeY, std::string& path);
    void read_unsigned_vector_from_csv(uint64_t* buffer, uint32_t shapeY, std::string& path);

    // evaluate polynomials "efficiently"
    long double evaluate_horner(long double input, const long double* coefs, uint64_t size);


}

#endif //FBS_UTILS_H
