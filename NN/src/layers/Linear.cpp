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

        std::vector<CiphertextCRT> accu(shapeX);
        std::vector<CiphertextCRT> result(shapeX);

#pragma omp parallel for
        for(uint32_t i = 0; i < shapeX; i++) {
            auto accu_ct = CryptData.EncryptCRT(B_v[i] % moduli[0], fbscrypto::CIPHERTEXT_STATE::TRIVIAL_BEFORE_KEYSWITCH);
            for(uint32_t j = 0; j < shapeY; j++) {
                auto tmp = (*tensor1D)[j] * this->W_m[j][i];
                accu_ct += tmp;
            }
            accu[i] = std::move(accu_ct);
        }

        if (activation == ACTIVATION::SOFTMAX) {
            std::vector<int64_t> tmp;
            auto shape = tensor1D->GetShape();
            std::vector<PlaintextCRT> decrypted_tensor(shape);
            auto modulus2 = CryptData.GetModuli()[0] >> 1;

#pragma omp parallel for
            for(uint32_t i = 0; i < tensor1D->GetShape(); i++) {
                auto tmp1 = CryptData.DoKeySwitch(accu[i]);
                decrypted_tensor[i] = std::move(CryptData.DecryptCRT(tmp1, fbscrypto::TRIVIAL));
            }

            for(auto& PT : decrypted_tensor) {
                int64_t value = PT.GetContents()[0];
                if (value >= modulus2) {
                    value -= modulus2;
                }
                tmp.push_back(value);
            }
            auto max_idx = std::distance(tmp.begin(), std::max_element(tmp.begin(), tmp.end()));

            // for our classification purpose we do not need the full probability distribution
            // of a softmax output. As softmax preserves the ordering, we output the maximum.
            for(uint32_t i = 0; i < shapeX; i++) {
                if (i == max_idx)
                    result[i] = std::move(CryptData.EncryptCRT(1));
                else
                    result[i] = std::move(CryptData.EncryptCRT(0));
            }
            return std::make_shared<CiphertextTensor1D>(result);
        }

        std::shared_ptr<CiphertextTensor> tensor_out = std::make_shared<CiphertextTensor1D>(accu);
        return CiphertextActivation::forward(tensor_out);

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
