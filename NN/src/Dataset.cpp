//
// Created by leonard on 11.08.21.
//

#include "Dataset.h"

namespace NN {
    std::vector<std::shared_ptr<PlaintextTensor1D>> read_plain_mnist100_1d(std::vector<uint64_t>& moduli, std::string& path) {
        constexpr uint32_t rows = 100;
        constexpr uint32_t columns = 784;
        uint64_t arr[rows * columns];

        read_unsigned_matrix_from_csv(arr, columns, rows, path);

        std::vector<std::shared_ptr<PlaintextTensor1D>> result(rows);
        for(uint32_t i = 0; i < rows; i++) {
            std::vector<PlaintextCRT> tmp;
            for(uint32_t j = 0; j < columns; j++) {
                tmp.emplace_back(arr[i * columns + j], moduli);
            }
            result[i] = std::make_shared<PlaintextTensor1D>(tmp);
        }
        return result;
    }

    std::vector<std::shared_ptr<CiphertextTensor1D>> read_encrypted_mnist100_1d(CryptoData& data, std::string& path) {

        std::vector<uint64_t> moduli = data.GetModuli();
        auto tmp = read_plain_mnist100_1d(moduli, path);
        std::vector<std::shared_ptr<CiphertextTensor1D>> results;
        for(auto& v : tmp) {
            std::vector<CiphertextCRT> entry;
            for(uint32_t i = 0; i < v->GetShape(); i++) {
                entry.push_back(data.EncryptCRT((*v)[i].GetContents(), fbscrypto::CIPHERTEXT_STATE::TRIVIAL_BEFORE_KEYSWITCH));
            }
            results.push_back(std::make_shared<CiphertextTensor1D>(entry));
        }

        return results;
    }

    std::vector<std::shared_ptr<PlaintextTensor3D>> read_plain_mnist100_3d(std::vector<uint64_t>& moduli, std::string& path) {
        constexpr uint32_t rows = 100;
        constexpr uint32_t columns = 784;
        uint64_t arr[rows * columns];

        read_unsigned_matrix_from_csv(arr, columns, rows, path);

        std::vector<std::shared_ptr<PlaintextTensor3D>> elements;
        for(uint32_t i = 0; i < rows; i++) {
            std::vector<std::vector<std::vector<PlaintextCRT>>> new_sample(1);
            new_sample[0] = std::vector<std::vector<PlaintextCRT>>(28);
            for(uint32_t c_row = 0; c_row < 28; c_row++) {
                std::vector<PlaintextCRT> current_row;
                for(uint32_t c_col = 0; c_col < 28; c_col++) {
                    current_row.emplace_back(arr[i * columns + 28 * c_row + c_col], moduli);
                }
                new_sample[0][c_row] = std::move(current_row);
            }
            elements.emplace_back(std::make_shared<PlaintextTensor3D>(new_sample));
        }

        return elements;
    }

    std::vector<std::shared_ptr<CiphertextTensor3D>> read_encrypted_mnist100_3d(CryptoData& data, std::string& path) {
        auto mods = data.GetModuli();
        auto tmp_data = read_plain_mnist100_3d(mods, path);

        std::vector<std::shared_ptr<CiphertextTensor3D>> results;
        for(auto& v : tmp_data) {
            std::vector<std::vector<std::vector<CiphertextCRT>>> entry(1);
            entry[0] = std::vector<std::vector<CiphertextCRT>>(28);
            for(uint32_t i = 0; i < 28; i++) {
                std::vector<CiphertextCRT> row;
                for(uint32_t j = 0; j < 28; j++) {
                    row.emplace_back(data.EncryptCRT((*v)[0][i][j].GetContents()));
                }
                entry[0][i] = std::move(row);
            }
            results.emplace_back(std::make_shared<CiphertextTensor3D>(entry));
        }

        return results;
    }

    std::vector<uint64_t> read_mnist100_labels(std::string& path) {

        std::vector<uint64_t> labels(100);
        read_unsigned_vector_from_csv(labels.data(), 100, path);

        return labels;
    }

}