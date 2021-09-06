//
// Created by leonard on 18.08.21.
//
#include "error.h"
#include "setup.h"

void measure_error(uint32_t idx, uint32_t mod_bits) {

    auto data = CryptoData(fbscrypto::FBSFHEPARAMSET_LIST[idx]);
    auto T = 1 << mod_bits;
    uint32_t n = 100;

    std::vector<fbscrypto::LWECiphertext> cts(n);

    auto msg = data.ctx.Encode(1, T, fbscrypto::CIPHERTEXT_STATE::FRESH);
    auto base_ct = data.ctx.Encrypt(data.key, msg);
    auto map = [T](uint64_t a) { return a; };
    auto bootsmap = fbscrypto::BootstrapFunction({map}, T);

#pragma omp parallel for
    for(uint32_t i = 0; i < n; i++){
        cts[i] = data.ctx.FullDomainBootstrap(base_ct, bootsmap, fbscrypto::SKIP_STEP::KEYSWITCH);
    }

    auto accu = data.ctx.Encrypt(data.key, 0, fbscrypto::CIPHERTEXT_STATE::TRIVIAL_BEFORE_KEYSWITCH);
    for(uint32_t i = 0; i < n; i++)
        (*accu) += (*cts[i]);

    auto res = data.ctx.Finalize(accu, fbscrypto::KEYSWITCH);
    int64_t plaintext = 0;
    data.ctx.Decrypt(data.key, res, &plaintext);

    std::cout << plaintext << " " << msg * (n % T) << std::endl;

}

void measure_all_errors() {
    for(uint32_t i = 0; i < 6; i++) {
        std::cout << "TESTING SET " << fbscrypto::FBSFHEPARAMSET_LIST[i] << std::endl;
        for(uint32_t m = 6; m <= 11; m++) {
            std::cout << "MODULUS = " << (1 << m) << std::endl;
            measure_error(i, m);
        }
    }
}