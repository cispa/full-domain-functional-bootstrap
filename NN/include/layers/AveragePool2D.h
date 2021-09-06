//
// Created by leonard on 07.08.21.
//

#ifndef FBS_AVERAGEPOOL2D_H
#define FBS_AVERAGEPOOL2D_H

#include "Layer.h"
#include "Utils.h"

namespace NN {
    namespace Layers {

        class PlaintextAveragePool2D : public PlaintextLayer {
        public:

            PlaintextAveragePool2D(std::vector<uint64_t>& moduli, uint64_t scale, uint64_t scale_inv, std::pair<uint32_t, uint32_t>& pool_size,
                                   std::pair<uint32_t, uint32_t>& stride, PADDING pad);

            void build_from_path(std::vector<std::string>& paths) override;

            std::shared_ptr<PlaintextTensor> forward(std::shared_ptr<PlaintextTensor>& input) override;

        private:

            std::pair<uint32_t, uint32_t> pool_size;
            std::pair<uint32_t, uint32_t> stride;
            PADDING pad;

        };

        class CiphertextAveragePool2D : public CiphertextLayer {
        public:
            CiphertextAveragePool2D(CryptoData& data, uint64_t scale, uint64_t scale_inv, std::pair<uint32_t, uint32_t> pool_size,
                                   std::pair<uint32_t, uint32_t> stride, PADDING pad);

            void build_from_path(std::vector<std::string>& paths) override;

            std::shared_ptr<CiphertextTensor> forward(std::shared_ptr<CiphertextTensor>& input) override;

        private:

            CryptoData& data;
            std::pair<uint32_t, uint32_t> pool_size;
            std::pair<uint32_t, uint32_t> stride;
            PADDING pad;

        };

    }
}

#endif //FBS_AVERAGEPOOL2D_H
