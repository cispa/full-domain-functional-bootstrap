//
// Created by leonard on 11.08.21.
//

#ifndef FBS_DATASET_H
#define FBS_DATASET_H

#include "Tensor.h"
#include "Utils.h"
#include <vector>

namespace NN {
    std::vector<std::shared_ptr<PlaintextTensor1D>> read_plain_mnist100_1d(std::vector<uint64_t>& moduli, std::string& path);

    std::vector<std::shared_ptr<CiphertextTensor1D>> read_encrypted_mnist100_1d(CryptoData& data, std::string& path);

    std::vector<std::shared_ptr<PlaintextTensor3D>> read_plain_mnist100_3d(std::vector<uint64_t>& moduli, std::string& path);

    std::vector<std::shared_ptr<CiphertextTensor3D>> read_encrypted_mnist100_3d(CryptoData& data, std::string& path);

    std::vector<uint64_t> read_mnist100_labels(std::string& path);

}

#endif //FBS_DATASET_H
