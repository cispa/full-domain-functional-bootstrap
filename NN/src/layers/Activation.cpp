//
// Created by leonard on 08.08.21.
//

#include "layers/Activation.h"
#include "ActivationFunctions.h"

#include <omp.h>

namespace NN {

    namespace Layers {

        PlaintextActivation::PlaintextActivation(std::vector<uint64_t> &moduli, uint64_t scale, uint64_t scale_inv, ACTIVATION activation, bool do_scale)
                : PlaintextLayer(moduli, scale, scale_inv), activation(activation) {
            if(this->moduli.size() > 1 && (activation != ACTIVATION::TANH_POLY)
               && (activation != ACTIVATION::SIGMOID_POLY) && (activation != ACTIVATION::RELU_POLY)
               && (activation != ACTIVATION::NONE)) {
                std::cerr << "Using activation functions that are not approximated by polynomials for |moduli| > 1 is"
                             "can go wrong. Proceed with caution..." << std::endl;
            }

            switch (activation) {
                case ACTIVATION::RELU: {
                    F = [this](uint64_t v, uint64_t q) ->uint64_t {

                        if (v > (q / 2)) return 0ull;

                        long double dv = v;
                        auto quot = dv / double(this->scale);
                        long double frac;
                        if (std::modf(quot, &frac) > 0.5)
                            return uint64_t(std::ceil(quot));
                        else
                            return uint64_t(std::floor(quot));
                        //return (v > (q / 2)) ? 0 : std::round(dv / double(this->scale));
                    };
                    break;
                };
                case ACTIVATION::RELU_POLY: {
                    F = [](uint64_t v, uint64_t q) {
                        return RELU_POLY(v);
                    };
                    break;
                }
                case ACTIVATION::TANH: {
                    F = [](uint64_t v, uint64_t q) {
                        return TANH(v);
                    };
                    break;
                }
                case ACTIVATION::TANH_POLY: {
                    F = [](uint64_t v, uint64_t q) {
                        return TANH_POLY(v);
                    };
                    break;
                }
                case ACTIVATION::SIGMOID: {
                    F = [](uint64_t v, uint64_t q) {
                        return TANH(v);
                    };
                    break;
                }
                case ACTIVATION::SIGMOID_POLY: {
                    F = [](uint64_t v, uint64_t q) {
                        return TANH(v);
                    };
                    break;
                }
                default: {
                    F = [](uint64_t v, uint64_t q) {return v; };
                }
            }

        }

        void PlaintextActivation::build_from_path(std::vector<std::string> &paths) {
            throw std::runtime_error("No need to build Activation layer.");
        }

        void PlaintextActivation::compute_activation_1d(std::shared_ptr<PlaintextTensor1D>& tensor1D) {

            auto shape = tensor1D->GetShape();

            if ((shape == 0) || (this->moduli.empty()))
                return;

            if(activation == ACTIVATION::SOFTMAX) {
                // for the softmax in the final layer
                // we compute in "plaintext", so we have to do it within the linear layer part
                return;
            }

            else {
                for(uint32_t i = 0; i < shape; i++) {
                    auto& elem = (*tensor1D)[i].GetContents();
                    for(uint32_t j = 0; j < this->moduli.size(); j++) {
                        elem[j] = F(elem[j], this->moduli[j]);
                    }
                }
            }
        }

        void PlaintextActivation::compute_activation_2d(std::shared_ptr<PlaintextTensor2D>& tensor2D) {
            auto shape = tensor2D->GetShape();
            if ((shape.first == 0) || (shape.second == 0) || (this->moduli.empty()))
                return;

            for(uint32_t i = 0; i < shape.second; i++) {
                for(uint32_t j = 0; j < shape.first; j++) {
                    auto& coefs = (*tensor2D)[i][j].GetContents();
                    for(uint32_t k = 0; k < this->moduli.size(); k++) {
                        coefs[k] = F(coefs[k], this->moduli[k]);
                    }
                }
            }
        }

        void PlaintextActivation::compute_activation_3d(std::shared_ptr<PlaintextTensor3D>& tensor3D) {
            uint32_t shapeX, shapeY, shapeZ;
            std::tie(shapeX,shapeY,shapeZ) = tensor3D->GetShape();
            for(uint32_t h = 0; h < shapeZ; h++) {
                for(uint32_t i = 0; i < shapeY; i++) {
                    for(uint32_t j = 0; j < shapeX; j++) {
                        auto& coefs = (*tensor3D)[h][i][j].GetContents();
                        for(uint32_t k = 0; k < this->moduli.size(); k++) {
                            coefs[k] = F(coefs[k], this->moduli[k]);
                        }
                    }
                }
            }
        }

        std::shared_ptr<PlaintextTensor> PlaintextActivation::forward(std::shared_ptr<PlaintextTensor> &tensor) {

            std::shared_ptr<PlaintextTensor1D> tensor1D;
            std::shared_ptr<PlaintextTensor2D> tensor2D;
            std::shared_ptr<PlaintextTensor3D> tensor3D;

            if (activation != ACTIVATION::NONE) {
                if((tensor1D = std::dynamic_pointer_cast<PlaintextTensor1D>(tensor)) != nullptr) {
                    compute_activation_1d(tensor1D);
                    return tensor1D;
                }

                if ((tensor2D = std::dynamic_pointer_cast<PlaintextTensor2D>(tensor)) != nullptr) {
                    compute_activation_2d(tensor2D);
                    return tensor2D;
                }

                if ((tensor3D = std::dynamic_pointer_cast<PlaintextTensor3D>(tensor)) != nullptr) {
                    compute_activation_3d(tensor3D);
                    return tensor3D;
                }
            }

            return tensor;
        }

        // Ciphertext

        CiphertextActivation::CiphertextActivation(CryptoData& data, uint64_t scale, uint64_t scale_inv, ACTIVATION activation, bool do_scale)
                : CiphertextLayer(data.GetModuli(), scale, scale_inv), data(data), activation(activation) {


            if(this->moduli.size() > 1 && (activation != ACTIVATION::TANH_POLY)
               && (activation != ACTIVATION::SIGMOID_POLY) && (activation != ACTIVATION::RELU_POLY)
               && (activation != ACTIVATION::NONE)) {
                std::cerr << "Using activation functions that are not approximated by polynomials for |moduli| > 1 is"
                             "can go wrong. Proceed with caution..." << std::endl;
            }

            std::function<uint64_t(uint64_t, uint64_t)> F;
            switch (activation) {
                case ACTIVATION::NONE: {
                    F = [](uint64_t v, uint64_t q) {
                        return v;
                    };
                    break;
                }
                case ACTIVATION::RELU: {
                    F = [this](uint64_t v, uint64_t q) ->uint64_t {

                        if (v >= (q / 2)) return 0ull;

                        long double dv = v;
                        auto quot = dv / double(this->scale);
                        long double frac;
                        if (std::modf(quot, &frac) > 0.5)
                            return uint64_t(std::ceil(quot));
                        else
                            return uint64_t(std::floor(quot));
                        //return (v > (q / 2)) ? 0 : std::round(dv / double(this->scale));
                    };
                    break;
                };
                case ACTIVATION::RELU_POLY: {
                    F = [](uint64_t v, uint64_t q) {
                        return RELU_POLY(v);
                    };
                    break;
                }
                case ACTIVATION::TANH: {
                    F = [](uint64_t v, uint64_t q) {
                        return TANH(v);
                    };
                    break;
                }
                case ACTIVATION::TANH_POLY: {
                    F = [](uint64_t v, uint64_t q) {
                        return TANH_POLY(v);
                    };
                    break;
                }
                case ACTIVATION::SIGMOID: {
                    F = [](uint64_t v, uint64_t q) {
                        return TANH(v);
                    };
                    break;
                }
                case ACTIVATION::SIGMOID_POLY: {
                    F = [](uint64_t v, uint64_t q) {
                        return TANH(v);
                    };
                    break;
                }
                default: {
                    F = [](uint64_t v, uint64_t q) {return v; };
                }
            }

            for(auto& modulus : this->moduli)
                EF.emplace_back([F, modulus](uint64_t v) {return (F(v, modulus)) % modulus;}, modulus);
        }

        void CiphertextActivation::build_from_path(std::vector<std::string> &paths) {
            throw std::runtime_error("No need to build anything for activation layer");
        }

        void CiphertextActivation::compute_activation_1d(shared_ptr<CiphertextTensor1D> &tensor1D) {

            auto shape = tensor1D->GetShape();

            if ((shape == 0) || (this->moduli.empty()))
                return;

#pragma omp parallel for
            for(uint32_t i = 0; i < shape; i++) {
                CiphertextCRT tmp = data.DoKeySwitch((*tensor1D)[i]);
                auto dec = data.DecryptCRT(tmp, fbscrypto::TRIVIAL);
                (*tensor1D)[i] = data.BootstrapCRT(tmp, EF, fbscrypto::SKIP_STEP::KEYSWITCH);
            }

        }

        void CiphertextActivation::compute_activation_2d(shared_ptr<CiphertextTensor2D> &tensor2D) {

            auto shape = tensor2D->GetShape();
            if ((shape.first == 0) || (shape.second == 0) || (this->moduli.empty()))
                return;

#pragma omp parallel for collapse(2)
            for(uint32_t i = 0; i < shape.second; i++) {
                for(uint32_t j = 0; j < shape.first; j++) {
                    (*tensor2D)[i][j] = data.BootstrapCRT((*tensor2D)[i][j], EF);
                }
            }
        }

        void CiphertextActivation::compute_activation_3d(shared_ptr<CiphertextTensor3D> &tensor3D) {
            uint32_t shapeX, shapeY, shapeZ;
            std::tie(shapeX,shapeY,shapeZ) = tensor3D->GetShape();

#pragma omp parallel for collapse(3)
            for(uint32_t h = 0; h < shapeZ; h++) {
                for(uint32_t i = 0; i < shapeY; i++) {
                    for(uint32_t j = 0; j < shapeX; j++) {
                        auto tmp = data.DoKeySwitch((*tensor3D)[h][i][j]);
                        (*tensor3D)[h][i][j] = data.BootstrapCRT(tmp, EF, fbscrypto::SKIP_STEP::KEYSWITCH);
                    }
                }
            }
        }

        std::shared_ptr<CiphertextTensor> CiphertextActivation::forward(std::shared_ptr<CiphertextTensor> &tensor) {
            std::shared_ptr<CiphertextTensor1D> tensor1D;
            std::shared_ptr<CiphertextTensor2D> tensor2D;
            std::shared_ptr<CiphertextTensor3D> tensor3D;

                if((tensor1D = std::dynamic_pointer_cast<CiphertextTensor1D>(tensor)) != nullptr) {
                    compute_activation_1d(tensor1D);
                    return tensor1D;
                }

                if ((tensor2D = std::dynamic_pointer_cast<CiphertextTensor2D>(tensor)) != nullptr) {
                    compute_activation_2d(tensor2D);
                    return tensor2D;
                }

                if ((tensor3D = std::dynamic_pointer_cast<CiphertextTensor3D>(tensor)) != nullptr) {
                    compute_activation_3d(tensor3D);
                    return tensor3D;
                }

            return tensor;
        }
    }
}