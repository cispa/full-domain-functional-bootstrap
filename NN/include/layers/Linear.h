//
// Created by leonard on 27.07.21.
//

#ifndef FBS_LINEAR_H
#define FBS_LINEAR_H

#include "Layer.h"
#include "Tensor.h"
#include "Utils.h"

#include "Activation.h"

namespace NN {
    namespace Layers {

        class PlaintextLinear : public PlaintextActivation {

        public:

            PlaintextLinear(std::vector<uint64_t>& mod, uint64_t scale, uint64_t scale_inv, uint32_t shapeX, uint32_t shapeY, ACTIVATION activation) : PlaintextActivation(mod, scale, scale_inv, activation), shapeX(shapeX), shapeY(shapeY) {
                W_m = std::vector<std::vector<int64_t>>(shapeY);
                B_v = std::vector<int64_t>(shapeX);
                for(uint32_t i = 0; i < shapeY; i++)
                    W_m[i] = std::vector<int64_t>(shapeX);

            }

            std::shared_ptr<PlaintextTensor> forward(std::shared_ptr<PlaintextTensor>& tens) override;

            void build_from_path(std::vector<std::string> &paths) override;

        private:

            uint32_t shapeX, shapeY;
            std::vector<std::vector<int64_t>> W_m;
            std::vector<int64_t> B_v;

        };

        class CiphertextLinear : public CiphertextActivation {

        public:

            CiphertextLinear(CryptoData& data, uint64_t scale, uint64_t scale_inv, uint32_t shapeX, uint32_t shapeY, ACTIVATION activation) : CiphertextActivation(data, scale, scale_inv, activation), CryptData(data), shapeX(shapeX), shapeY(shapeY) {
                W_m = std::vector<std::vector<int64_t>>(shapeY);
                B_v = std::vector<int64_t>(shapeX);
                for(uint32_t i = 0; i < shapeY; i++)
                    W_m[i] = std::vector<int64_t>(shapeX);

            }

            std::shared_ptr<CiphertextTensor> forward(std::shared_ptr<CiphertextTensor>& tens) override;

            void build_from_path(std::vector<std::string> &paths) override;

        private:

            CryptoData& CryptData;
            uint32_t shapeX, shapeY;
            std::vector<std::vector<int64_t>> W_m;
            std::vector<int64_t> B_v;
        };

    }
}

#endif //FBS_LINEAR_H
