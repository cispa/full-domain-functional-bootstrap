//
// Created by leonard on 27.07.21.
//

#ifndef FBS_NETWORK_H
#define FBS_NETWORK_H

#include "Layer.h"
#include "layers/Activation.h"
#include "nlohmann/json.hpp"

using json = nlohmann::json;

namespace NN {

    enum class LAYER_TYPES {
        CONV2D,
        AVG2D,
        DENSE,
        FLATTEN
    };

    LAYER_TYPES resolve_layer(std::string& input);

    Layers::ACTIVATION resolve_activation(std::string& input);

    template<typename TensorType, typename LayerType>
    class Network {

    public:

        Network() = default;

        std::shared_ptr<TensorType> run(std::shared_ptr<TensorType>& input) {
            for(auto& layer : layers) {
                input = layer->forward(input);

                /*
                if (std::is_same<TensorType, PlaintextTensor>::value){
                    auto pt_tensor = input;
                    if (pt_tensor->GetDimensions() == 1) {
                        auto t1d = std::dynamic_pointer_cast<PlaintextTensor1D>(pt_tensor);
                        std::cout << (*t1d) << std::endl;
                    } else if (pt_tensor->GetDimensions() == 2) {
                        auto t2d = std::dynamic_pointer_cast<PlaintextTensor2D>(pt_tensor);
                        std::cout << (*t2d) << std::endl;
                    } else {
                        auto t3d = std::dynamic_pointer_cast<PlaintextTensor3D>(pt_tensor);
                        std::cout << (*t3d) << std::endl;
                    }
                } else {


                }
                */
            }

            return input;
        }

        void add_layer(std::shared_ptr<LayerType>& layer) {
            layers.push_back(layer);
        }

        const std::vector<std::shared_ptr<LayerType>>& GetLayers() {
            return layers;
        }

        virtual void build_from_directory(std::string dir) = 0;

    protected:

        std::vector<std::shared_ptr<LayerType>> layers{};

    };

    class PlaintextNetwork : public Network<PlaintextTensor, Layers::PlaintextLayer> {

    public:

        PlaintextNetwork(std::vector<uint64_t>& moduli) : moduli(moduli) {};

        void build_from_directory(std::string dir) override;

    private:

        std::vector<uint64_t> moduli;

    };

    class CiphertextNetwork : public Network<CiphertextTensor, Layers::CiphertextLayer> {
    public:
        explicit CiphertextNetwork(CryptoData& data) : data(data) {};

        void build_from_directory(std::string dir) override;

    private:

        CryptoData& data;

    };


}

#endif //FBS_NETWORK_H
