//
// Created by leonard on 09.08.21.
//

#include "Network.h"
#include "layers/Linear.h"
#include "layers/AveragePool2D.h"
#include "layers/Convolve2D.h"
#include "layers/Flatten.h"

namespace NN {

    LAYER_TYPES resolve_layer(std::string& input) {

        if (input == "conv2d")
            return LAYER_TYPES::CONV2D;
        else if (input == "avg_pool2d")
            return LAYER_TYPES::AVG2D;
        else if (input == "dense")
            return LAYER_TYPES::DENSE;
        else if (input == "flatten")
            return LAYER_TYPES::FLATTEN;

        std::string message = "Invalid layer string: ";
        message.append(input);

        throw std::invalid_argument(message);
    }

    Layers::ACTIVATION resolve_activation(std::string& input) {
        if ((input == "relu") or (input == "relu_modulo"))
            return Layers::ACTIVATION::RELU;
        if ((input == "softmax") or (input == "softmax_modulo"))
            return Layers::ACTIVATION::SOFTMAX;
        if ((input == "tanh") or (input == "tanh_modulo"))
            return Layers::ACTIVATION::TANH;
        if ((input == "sigmoid") or (input == "sigmoid_modulo"))
            return Layers::ACTIVATION::SIGMOID;

        return Layers::ACTIVATION::NONE;
    }

    void PlaintextNetwork::build_from_directory(std::string model_dir) {

        std::ifstream config_stream;
        if (model_dir.back() != '/')
            model_dir.append("/");

        auto dir = model_dir;

        dir.append("config.json");

        config_stream.open(dir);

        if (!config_stream) {
            std::cerr << "Could not open file: " << dir << std::endl;
            std::exit(-1);
        }

        auto config = json::parse(config_stream);

        std::vector<std::string> paths(2);
        for(uint32_t i = 0; i < config.size(); i++) {

            auto& current_layer = config[i];

            std::string layer_name = current_layer["name"];

            auto layer_type = resolve_layer(layer_name);

            switch (layer_type) {
                case LAYER_TYPES::DENSE: {

                    std::string activation_str = current_layer["activation"];

                    paths[0] = current_layer["weights"];
                    paths[1] = current_layer["bias"];

                    paths[0].insert(0, model_dir);
                    paths[1].insert(0, model_dir);

                    uint32_t shapeX = current_layer["columns"];
                    uint32_t shapeY = current_layer["rows"];
                    uint64_t scale = current_layer["scale"];
                    uint64_t scale_inv = current_layer["scale_inv"];

                    // risky

                    auto activation = resolve_activation(activation_str);

                    std::shared_ptr<Layers::PlaintextLayer> dense =
                            std::make_shared<Layers::PlaintextLinear>(moduli, scale, scale_inv, shapeX, shapeY, activation);
                    dense->build_from_path(paths);

                    this->layers.push_back(dense);
                    break;
                }
                case LAYER_TYPES::FLATTEN: {
                    std::shared_ptr<Layers::PlaintextLayer> flatten = std::make_shared<Layers::PlaintextFlatten>();
                    this->layers.push_back(flatten);
                    break;
                }
                case LAYER_TYPES::AVG2D: {

                    Layers::PADDING pad;
                    if (current_layer["padding"] == "same")
                        pad = Layers::PADDING::SAME;
                    else
                        pad = Layers::PADDING::VALID;

                    auto stride = current_layer["strides"];
                    auto pool_size = current_layer["pool_size"];

                    auto stride_tuple = std::make_pair<uint32_t, uint32_t>(stride[1], stride[0]);
                    auto pool_size_tuple = std::make_pair<uint32_t, uint32_t>(pool_size[1], pool_size[0]);

                    uint64_t scale = current_layer["scale"];
                    uint64_t scale_inv = current_layer["scale_inv"];


                    std::shared_ptr<Layers::PlaintextLayer> pool2D =
                            std::make_shared<Layers::PlaintextAveragePool2D>(moduli, scale, scale_inv, pool_size_tuple, stride_tuple, pad);

                    this->layers.push_back(pool2D);
                    break;
                }

                case LAYER_TYPES::CONV2D: {
                    std::string activation_str = current_layer["activation"];
                    auto activation = resolve_activation(activation_str);

                    Layers::PADDING pad;
                    if (current_layer["padding"] == "same")
                        pad = Layers::PADDING::SAME;
                    else
                        pad = Layers::PADDING::VALID;

                    paths[0] = current_layer["weights"];
                    paths[1] = current_layer["bias"];

                    paths[0].insert(0, model_dir);
                    paths[1].insert(0, model_dir);

                    uint64_t scale = current_layer["scale"];
                    uint64_t scale_inv = current_layer["scale_inv"];


                    uint32_t n_filters = current_layer["filters"];
                    uint32_t channels = current_layer["channels"];

                    auto stride = current_layer["strides"];
                    auto pool_size = current_layer["kernel_size"];
                    auto stride_tuple = std::make_pair<uint32_t, uint32_t>(stride[1], stride[0]);
                    auto pool_size_tuple = std::make_pair<uint32_t, uint32_t>(pool_size[1], pool_size[0]);

                    std::shared_ptr<Layers::PlaintextLayer> conv2D =
                            std::make_shared<Layers::PlaintextConvolve2D>(moduli, scale, scale_inv, channels, n_filters, pool_size_tuple, stride_tuple,
                                                                          pad, activation);

                    conv2D->build_from_path(paths);
                    layers.push_back(conv2D);
                    break;
                }
            }

        }
    }

    void CiphertextNetwork::build_from_directory(std::string model_dir) {

            std::ifstream config_stream;

            if (model_dir.back() != '/')
                model_dir.append("/");

            auto dir = model_dir;
            dir.append("config.json");

            config_stream.open(dir);

            if (!config_stream) {
                std::cerr << "Could not open file: " << dir << std::endl;
                std::exit(-1);
            }

            auto config = json::parse(config_stream);

            std::vector<std::string> paths(2);
            for(uint32_t i = 0; i < config.size(); i++) {

                auto& current_layer = config[i];

                std::string layer_name = current_layer["name"];

                auto layer_type = resolve_layer(layer_name);

                switch (layer_type) {
                    case LAYER_TYPES::DENSE: {

                        std::string activation_str = current_layer["activation"];

                        paths[0] = current_layer["weights"];
                        paths[1] = current_layer["bias"];

                        paths[0].insert(0, model_dir);
                        paths[1].insert(0, model_dir);

                        uint32_t shapeX = current_layer["columns"];
                        uint32_t shapeY = current_layer["rows"];
                        uint64_t scale = current_layer["scale"];
                        uint64_t scale_inv = current_layer["scale_inv"];

                        std::vector<uint64_t> moduli = data.GetModuli();

                        auto activation = resolve_activation(activation_str);

                        std::shared_ptr<Layers::CiphertextLayer> dense =
                                std::make_shared<Layers::CiphertextLinear>(data, scale, scale_inv, shapeX, shapeY, activation);
                        dense->build_from_path(paths);

                        this->layers.push_back(dense);
                        break;
                    }
                    case LAYER_TYPES::FLATTEN: {
                        std::shared_ptr<Layers::CiphertextLayer> flatten = std::make_shared<Layers::CiphertextFlatten>();
                        this->layers.push_back(flatten);
                        break;
                    }
                    case LAYER_TYPES::AVG2D: {

                        Layers::PADDING pad;
                        if (current_layer["padding"] == "same")
                            pad = Layers::PADDING::SAME;
                        else
                            pad = Layers::PADDING::VALID;

                        auto stride = current_layer["strides"];
                        auto pool_size = current_layer["pool_size"];

                        auto stride_tuple = std::make_pair<uint32_t, uint32_t>(stride[1], stride[0]);
                        auto pool_size_tuple = std::make_pair<uint32_t, uint32_t>(pool_size[1], pool_size[0]);

                        uint64_t scale = current_layer["scale"];
                        uint64_t scale_inv = current_layer["scale_inv"];


                        std::shared_ptr<Layers::CiphertextLayer> pool2D =
                                std::make_shared<Layers::CiphertextAveragePool2D>(data, scale, scale_inv, pool_size_tuple, stride_tuple, pad);

                        this->layers.push_back(pool2D);
                        break;
                    }

                    case LAYER_TYPES::CONV2D: {
                        std::string activation_str = current_layer["activation"];
                        auto activation = resolve_activation(activation_str);

                        Layers::PADDING pad;
                        if (current_layer["padding"] == "same")
                            pad = Layers::PADDING::SAME;
                        else
                            pad = Layers::PADDING::VALID;

                        paths[0] = current_layer["weights"];
                        paths[1] = current_layer["bias"];

                        paths[0].insert(0, model_dir);
                        paths[1].insert(0, model_dir);

                        uint64_t scale = current_layer["scale"];
                        uint64_t scale_inv = current_layer["scale_inv"];

                        uint32_t n_filters = current_layer["filters"];
                        uint32_t channels = current_layer["channels"];

                        auto stride = current_layer["strides"];
                        auto pool_size = current_layer["kernel_size"];
                        auto stride_tuple = std::make_pair<uint32_t, uint32_t>(stride[1], stride[0]);
                        auto pool_size_tuple = std::make_pair<uint32_t, uint32_t>(pool_size[1], pool_size[0]);

                        std::shared_ptr<Layers::CiphertextLayer> conv2D =
                                std::make_shared<Layers::CiphertextConvolve2D>(data, scale, scale_inv, channels, n_filters, pool_size_tuple, stride_tuple,
                                                                              pad, activation);

                        conv2D->build_from_path(paths);
                        layers.push_back(conv2D);
                        break;
                    }
                }

            }
        }


}