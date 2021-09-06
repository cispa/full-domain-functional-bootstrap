//
// Created by leonard on 27.07.21.
//

#ifndef FBS_LAYER_H
#define FBS_LAYER_H

#include <string>
#include <utility>
#include <vector>

#include "Tensor.h"

namespace NN {

    namespace Layers {

        enum PADDING {
            VALID,
            SAME
        };

        template<typename IType>
        class TLayer {

        public:

            TLayer(std::vector<uint64_t> moduli, uint64_t scale = 0, uint64_t scale_inverse = 0)
            : moduli(std::move(moduli)), scale(scale), scale_inverse(scale_inverse) {};

            virtual void build_from_path(std::vector<std::string> &paths) = 0;

            virtual std::shared_ptr<IType> forward(std::shared_ptr<IType> &input) = 0;

        protected:

            uint64_t scale, scale_inverse;

            std::vector<uint64_t> moduli;

        };

        using PlaintextLayer = TLayer<PlaintextTensor>;
        using CiphertextLayer = TLayer<CiphertextTensor>;

    }

}

#endif //FBS_LAYER_H
