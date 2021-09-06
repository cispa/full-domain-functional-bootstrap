//
// Created by leonard on 07.05.21.
//

#include "implementation.h"

void time_parameter_set(fbscrypto::FBSFHEPARAMSET set, std::string name) {
    CryptoData data(set);
    uint32_t dummy = 42;
    int64_t pt;
    NativeInteger enc = data.ctx.Encode(dummy, 64, fbscrypto::FRESH);
    auto ct = data.ctx.Encrypt(data.key, enc.ConvertToInt());

    auto start = std::chrono::high_resolution_clock::now();

    auto bst = data.ctx.Bootstrap(ct);

    auto stop = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(stop-start);

    data.ctx.Decrypt(data.key, bst, &pt);
    auto res = data.ctx.Decode(pt, 64);

    std::cerr << "[" << name << "]" << " Bootstrap took " << elapsed.count() << "ms" << std::endl;
}

void time_binary_parameter_set(fbscrypto::FBSFHEPARAMSET set, std::string name) {
    CryptoData data(set);
    uint32_t dummy = 1;
    auto ct = data.ctx.Encrypt(data.key, dummy);

    auto start = std::chrono::high_resolution_clock::now();

    volatile auto bst = data.ctx.BootstrapBinary(ct);

    auto stop = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(stop-start);

    std::cerr << "[" << name << "]" << " Bootstrap took " << elapsed.count() << "ms" << std::endl;
}
