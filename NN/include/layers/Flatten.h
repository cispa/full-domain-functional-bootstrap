//
// Created by leonard on 08.08.21.
//

#ifndef FBS_FLATTEN_H
#define FBS_FLATTEN_H

#include "Layer.h"

namespace NN {
    namespace Layers {

        template<typename IType>
        class Flatten : public TLayer<TTensor<IType>> {

        public:
            Flatten() : TLayer<TTensor<IType>>({}) {}

            void build_from_path(std::vector<std::string>& path) override {
                throw std::runtime_error("Build from path is unnecessary for Flatten layer");
            }

            std::shared_ptr<TTensor1D<IType>> flatten2d(std::shared_ptr<TTensor2D<IType>>& input) {
                auto shape = input->GetShape();
                std::vector<IType> result;
                for(uint32_t i = 0; i < shape.second; i++) {
                    for(uint32_t j = 0; j < shape.first; j++) {
                        // Todo: use move constructor
                        result.emplace_back((*input)[i][j]);
                    }
                }

                return std::make_shared<TTensor1D<IType>>(result);
            }

            std::shared_ptr<TTensor1D<IType>> flatten3d(std::shared_ptr<TTensor3D<IType>>& tensor) {
                uint32_t shapeX, shapeY,shapeZ;
                auto input = move_channels_backward(tensor);
                std::tie(shapeX, shapeY, shapeZ) = input->GetShape();

                std::vector<IType> result;
                for(uint32_t i = 0; i < shapeZ; i++) {
                    for(uint32_t j = 0; j < shapeY; j++) {
                        for(uint32_t k = 0; k < shapeX; k++) {
                            // todo: use move constructor
                            result.emplace_back((*input)[i][j][k]);
                        }
                    }
                }

                return std::make_shared<TTensor1D<IType>>(result);
            }

            std::shared_ptr<TTensor<IType>> forward(std::shared_ptr<TTensor<IType>>& input) override {

                std::shared_ptr<TTensor2D<IType>> tensor2D;
                std::shared_ptr<TTensor3D<IType>> tensor3D;

                if((tensor2D = std::dynamic_pointer_cast<TTensor2D<IType>>(input)) != nullptr) {
                    return flatten2d(tensor2D);
                } else if((tensor3D = std::dynamic_pointer_cast<TTensor3D<IType>>(input)) != nullptr) {
                    return flatten3d(tensor3D);
                } else {
                    // in this case we have a 1D tensor, so no need to do anything;
                    return input;
                }

            }
        };

        using PlaintextFlatten = Flatten<PlaintextCRT>;
        using CiphertextFlatten = Flatten<CiphertextCRT>;

    }
}

#endif //FBS_FLATTEN_H
