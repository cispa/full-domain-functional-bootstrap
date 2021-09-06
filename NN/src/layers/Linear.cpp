//
// Created by leonard on 27.07.21.
//

#include "layers/Linear.h"

namespace NN {

    std::shared_ptr<PlaintextTensor> Layers::PlaintextLinear::forward(std::shared_ptr<PlaintextTensor> &tens) {

        std::shared_ptr<PlaintextTensor1D> tensor1D = std::dynamic_pointer_cast<PlaintextTensor1D>(tens);
        auto shape = tensor1D->GetShape();

        std::vector<PlaintextCRT> result(shapeX);
        if (this->activation != ACTIVATION::SOFTMAX) {
#pragma omp parallel for
            for(uint32_t i = 0; i < shapeX; i++) {
                auto accu = PlaintextCRT(B_v[i] % this->moduli[0], this->moduli);
                for(uint32_t j = 0; j < shapeY; j++) {
                    accu += (*tensor1D)[j] * this->W_m[j][i];
                }
                result[i] = std::move(accu);
            }
        } else {
            // assume 1 modulus, otherwise softmax doesn't make sense...
            std::vector<long double> tmp;
            for(uint32_t i = 0; i < shapeX; i++) {
                auto accu = (long double)(B_v[i]);
                for(uint32_t j = 0; j < shapeY; j++) {
                    accu += (long double)((*tensor1D)[j].at(0)) * this->W_m[j][i];
                }
                tmp.push_back(accu);
            }

            auto max_idx = std::distance(tmp.begin(), std::max_element(tmp.begin(), tmp.end()));
            for(uint32_t i = 0; i < shapeX; i++) {
                if (i == max_idx)
                    result[i] = PlaintextCRT(1, this->moduli);
                else
                    result[i] = PlaintextCRT(0, this->moduli);
            }
        }

        std::shared_ptr<PlaintextTensor> tmp = std::make_shared<PlaintextTensor1D>(result);

        //return tmp;
        return PlaintextActivation::forward(tmp);
    }

    void Layers::PlaintextLinear::build_from_path(std::vector<std::string> &paths) {


        if (paths.size() < 2) {
            throw std::invalid_argument("Linear layer expects two paths. One for W, one for B");
        }

        auto W = new int64_t[shapeX * shapeY];

        read_signed_matrix_from_csv(W, shapeX, shapeY, paths[0]);
        read_signed_vector_from_csv(B_v.data(), shapeX, paths[1]);

        for(uint32_t i = 0; i < shapeX; i++) {
            for(uint32_t j = 0; j < shapeY; j++) {
                W_m[j][i] = W[j * shapeX + i];
            }
        }

        delete[] W;
    }

    std::shared_ptr<CiphertextTensor> Layers::CiphertextLinear::forward(std::shared_ptr<CiphertextTensor> &tens) {

        std::shared_ptr<CiphertextTensor1D> tensor1D = std::dynamic_pointer_cast<CiphertextTensor1D>(tens);

        std::vector<CiphertextCRT> result(shapeX);
        if (activation != ACTIVATION::SOFTMAX) {
#pragma omp parallel for
            for(uint32_t i = 0; i < shapeX; i++) {
                auto accu = CryptData.EncryptCRT(B_v[i] % moduli[0], fbscrypto::CIPHERTEXT_STATE::TRIVIAL_BEFORE_KEYSWITCH);
                for(uint32_t j = 0; j < shapeY; j++) {
                    auto tmp = (*tensor1D)[j] * this->W_m[j][i];
                    accu += tmp;
                }
                result[i] = std::move(accu);
            }
        } else {
            // assume 1 modulus, otherwise softmax doesn't make sense...
            std::vector<long double> tmp(shapeX);
            auto shape = tensor1D->GetShape();
            std::vector<PlaintextCRT> decrypted_tensor(shape);

#pragma omp parallel for
            for(uint32_t i = 0; i < tensor1D->GetShape(); i++) {
                auto tmp1 = CryptData.DoKeySwitch((*tensor1D)[i]);
                decrypted_tensor[i] = std::move(CryptData.DecryptCRT(tmp1, fbscrypto::TRIVIAL));
            }

#pragma omp parallel for
            for(uint32_t i = 0; i < shapeX; i++) {
                auto accu = (long double)(B_v[i]);
                for(uint32_t j = 0; j < shapeY; j++) {
                    accu += (long double)(decrypted_tensor[j].at(0)) * this->W_m[j][i];
                }

                tmp[i] = accu;
            }

            auto max_idx = std::distance(tmp.begin(), std::max_element(tmp.begin(), tmp.end()));
            for(uint32_t i = 0; i < shapeX; i++) {
                if (i == max_idx)
                    result[i] = std::move(CryptData.EncryptCRT(3));
                else
                    result[i] = std::move(CryptData.EncryptCRT(0));
            }
            return std::make_shared<CiphertextTensor1D>(result);
        }

        std::shared_ptr<CiphertextTensor> tensor = std::make_shared<CiphertextTensor1D>(result);

        return CiphertextActivation::forward(tensor);

    }

    void Layers::CiphertextLinear::build_from_path(std::vector<std::string> &paths) {

        if (paths.size() < 2) {
            throw std::invalid_argument("Linear layer expects two paths. One for W, one for B");
        }

        auto W = new int64_t[shapeX * shapeY];

        read_signed_matrix_from_csv(W, shapeX, shapeY, paths[0]);
        read_signed_vector_from_csv(B_v.data(), shapeX, paths[1]);

        for(uint32_t i = 0; i < shapeX; i++) {
            for(uint32_t j = 0; j < shapeY; j++) {
                W_m[j][i] = W[j * shapeX + i];
            }
        };
    }

}
