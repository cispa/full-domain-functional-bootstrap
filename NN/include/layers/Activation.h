//
// Created by leonard on 08.08.21.
//

#ifndef FBS_ACTIVATION_H
#define FBS_ACTIVATION_H

#include "Layer.h"
#include "Tensor.h"
#include "Utils.h"

namespace NN {
    namespace Layers {

        enum class ACTIVATION {
            RELU,
            RELU_POLY,
            TANH,
            TANH_POLY,
            SIGMOID,
            SIGMOID_POLY,
            SOFTMAX,
            NONE
        };

        class PlaintextActivation : public PlaintextLayer {
        public:
            PlaintextActivation(std::vector<uint64_t>& moduli, uint64_t scale, uint64_t scale_inv, ACTIVATION activation, bool do_scale = true);

            std::shared_ptr<PlaintextTensor> forward(std::shared_ptr<PlaintextTensor>& tensor) override;

            void build_from_path(std::vector<std::string>& paths) override;

        private:

            void compute_activation_1d(shared_ptr<PlaintextTensor1D> &tensor1D);

            void compute_activation_2d(shared_ptr<PlaintextTensor2D> &tensor2D);

            void compute_activation_3d(shared_ptr<PlaintextTensor3D> &tensor3D);

            std::function<uint64_t(uint64_t, uint64_t)> F;

        protected:
            ACTIVATION activation;
        };

        class CiphertextActivation : public CiphertextLayer {
        public:
            CiphertextActivation(CryptoData& data, uint64_t scale, uint64_t scale_inv, ACTIVATION activation, bool do_scale = true);

            std::shared_ptr<CiphertextTensor> forward(std::shared_ptr<CiphertextTensor>& tensor) override;

            void build_from_path(std::vector<std::string>& paths) override;

        private:

            void compute_activation_1d(shared_ptr<CiphertextTensor1D> &tensor1D);

            void compute_activation_2d(shared_ptr<CiphertextTensor2D> &tensor2D);

            void compute_activation_3d(shared_ptr<CiphertextTensor3D> &tensor3D);

            CryptoData& data;
            std::vector<fbscrypto::BootstrapFunction> EF;
        protected:
            ACTIVATION activation;
        };
    }
}

#endif //FBS_ACTIVATION_H
