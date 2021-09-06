//
// Created by leonard on 08.08.21.
//

#ifndef FBS_PREBUILDNETWORKS_H
#define FBS_PREBUILDNETWORKS_H

#include "Network.h"
#include "Tensor.h"

#include <chrono>
#include <utility>

namespace NN {

    void run_mnist_1_plain(std::string path, uint64_t modulus, uint32_t n = 20);

    void run_mnist_2_plain(std::string path, uint64_t modulus, uint32_t n = 20);

    void run_mnist_1_encrypted(std::string path, uint64_t modulus, uint32_t paramset_idx, uint32_t n = 20);

    void run_mnist_2_encrypted(std::string path, uint64_t modulus, uint32_t paramset_idx, uint32_t n = 20);

}

#endif //FBS_PREBUILDNETWORKS_H
