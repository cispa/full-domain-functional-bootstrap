//
// Created by leonard on 09.05.21.
//

#include <cassert>
#include "functions.h"
#include <iostream>

#define TICK std::chrono::high_resolution_clock::now()

void time_addition_scalar_mul(fbscrypto::FBSFHEPARAMSET set, std::string name) {
    CryptoData data(set);

    fbscrypto::LWEPlaintext m1 = 5, m2 = 5;
    uint32_t rounds = 10;

    uint64_t total_sum = 0, total_scale = 0;

    for(uint32_t i = 0; i < rounds; i++) {

        auto ct1 = data.ctx.Encrypt(data.key, m1);
        auto ct2 = data.ctx.Encrypt(data.key, m2);

        auto start = TICK;

        auto sum = add_ciphertexts(ct1, ct2);

        auto step = TICK;

        auto scaled = scale_ciphertexts(ct1, 20);

        auto stop = TICK;

        auto sum_elapsed = std::chrono::duration_cast<std::chrono::microseconds>(step-start).count();
        auto sclale_elapsed = std::chrono::duration_cast<std::chrono::microseconds>(stop-step).count();
        total_sum += sum_elapsed;
        total_scale += sclale_elapsed;
    }

    std::cout << "Parameter set " << name << " took " << double(total_sum) / rounds << "us for addition and "
    << double(total_scale) / rounds << "us for scalar multiplication " << std::endl;

}


bool benchmark_functions() {
    for(uint32_t i = 0; i < 6; i++) {
        time_addition_scalar_mul(fbscrypto::FBSFHEPARAMSET_LIST[i], fbscrypto::FBSFHEPARAMSET_NAMES[i]);
    }

    return true;
}
