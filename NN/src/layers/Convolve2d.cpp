//
// Created by Leonard on 8/4/21.
//

#include "layers/Convolve2D.h"

#include "Utils.h"

namespace NN {
    namespace Layers {


        PlaintextConvolve2D::PlaintextConvolve2D(std::vector<uint64_t> &moduli, uint64_t scale, uint64_t scale_inv, uint32_t  n_channels, uint32_t n_filters,
                                                 std::pair<uint32_t, uint32_t>& kernel_size,
                                                 std::pair<uint32_t, uint32_t> &stride, PADDING pad, ACTIVATION activation)
                : PlaintextActivation(moduli, scale,scale_inv, activation), n_filters(n_filters), n_channels(n_channels), kernel_size(kernel_size),
                  stride(stride), pad(pad), bias(n_filters)
        {
        }

        void PlaintextConvolve2D::build_from_path(std::vector<std::string> &paths) {
            if (paths.size() < 2) {
                throw std::invalid_argument("Not enough paths to files to build layer");
            }

            auto* buffer = new int64_t[n_filters * kernel_size.first * kernel_size.second * n_channels];

            read_signed_matrix_from_csv(buffer, kernel_size.first * kernel_size.second * n_channels, n_filters , paths[0]);
            read_unsigned_vector_from_csv(bias.data(), n_filters, paths[1]);

            for(uint32_t i = 0; i < n_filters; i++) {
                auto start = buffer + i * kernel_size.first * kernel_size.second * n_channels;
                data.emplace_back(start, start + kernel_size.first * kernel_size.second * n_channels);
            }

            delete[] buffer;
        }

        std::shared_ptr<PlaintextTensor> PlaintextConvolve2D::forward(std::shared_ptr<PlaintextTensor>& input) {
            const std::shared_ptr<PlaintextTensor3D> tensor3D = std::dynamic_pointer_cast<PlaintextTensor3D>(input);

            uint32_t shapeX, shapeY, shapeZ;
            uint32_t output_y, output_x, padding_height, padding_width;
            uint32_t pad_t, pad_b, pad_l, pad_r;

            std::tie(shapeX, shapeY, shapeZ) = tensor3D->GetShape();

            // compute output parameters and padding
            if (this->pad == SAME) {
                output_y = std::ceil(double(shapeY) / this->stride.second);
                output_x = std::ceil(double(shapeX) / this->stride.first);
            } else {
                output_y = std::ceil(double(shapeY - kernel_size.second + 1) / this->stride.second);
                output_x = std::ceil(double(shapeX - kernel_size.first + 1) / this->stride.first);
            }

            if (shapeY % stride.second == 0) {
                padding_height = kernel_size.second > stride.second ? kernel_size.second - stride.second : 0;
            } else {
                padding_height = kernel_size.second > (stride.second % shapeY) ? kernel_size.second - (stride.second % shapeY) : 0;
            }

            if (shapeX % stride.first == 0) {
                padding_width = kernel_size.first > stride.first ? kernel_size.first - stride.first : 0;
            } else {
                padding_width = kernel_size.first > (stride.first % shapeX) ? kernel_size.first - (stride.first % shapeX) : 0;
            }

            pad_t = padding_height / 2;
            pad_b = padding_height - pad_t;

            pad_l = padding_width / 2;
            pad_r = padding_width - pad_l;

            // initialize output
            std::vector<std::vector<std::vector<PlaintextCRT>>> output(n_filters);
            for(uint32_t k = 0; k < n_filters; k++) {
                auto current_bias = bias[k];
                std::vector<std::vector<PlaintextCRT>> channel(output_y);
                for(uint32_t j = 0; j < output_y; j++) {
                    std::vector<PlaintextCRT> row;
                    for(uint32_t i = 0; i < output_x; i++) {
                        row.emplace_back(current_bias, this->moduli);
                    }
                    channel[j] = std::move(row);
                }
                output[k] = std::move(channel);
            }

            // pad input data
            if (pad == SAME) {
                pad_plaintext_tensor3d(this->moduli, tensor3D, pad_t, pad_b, pad_l, pad_r);
            }

            for(uint32_t f_i = 0; f_i < n_filters; f_i++) {
                // get current filter
                auto& filter = data[f_i];
                auto& output_i = output[f_i];

                // go over each output "pixel"
//#pragma omp parallel for collapse(2)
                for(uint32_t o_y = 0; o_y < output_y; o_y++) {
                    for(uint32_t o_x = 0; o_x < output_x; o_x++) {
                        PlaintextCRT output_yx = output_i[o_y][o_x];
                        // compute index in (padded) input
                        uint32_t i_x = o_x * stride.first;
                        uint32_t i_y = o_y * stride.second;

                        // do the convolution
                        for(uint32_t z = 0; z < n_channels; z++) {
                            for(uint32_t y = 0; y < kernel_size.second; y++) {
                                for(uint32_t x = 0; x < kernel_size.first; x++) {
                                    // filter index computation
                                    uint32_t filter_idx = x + y * kernel_size.first + z * kernel_size.second * kernel_size.first;
                                    auto& elem = (*tensor3D)[z][i_y + y][i_x + x];
                                    auto& f_elem = filter[filter_idx];
                                    output_yx += elem * f_elem;
                                    /*
                                    if (scale_inverse != 0) {
                                        output_yx += (elem * f_elem * int64_t(scale_inverse));

                                    } else {
                                        auto tmp = elem * f_elem;
                                        auto& contents = tmp.GetContents();
                                        for(uint32_t i = 0; i < this->moduli.size(); i++) {
                                            long double tmp = contents[i] > (this->moduli[i] / 2) ? int64_t(contents[i]) - int64_t(this->moduli[i]) : int64_t(contents[i]);
                                            tmp /= this->scale;
                                            contents[i] = tmp < 0 ? uint64_t(std::round(tmp)) + this->moduli[i] : uint64_t(std::round(tmp));
                                        }

                                        output_yx += tmp;
                                    }
                                    */
                                }
                            }
                        }
                        output_i[o_y][o_x] = std::move(output_yx);
                    }
                }

            }

            std::shared_ptr<PlaintextTensor> tensor = std::make_shared<PlaintextTensor3D>(output);

            return PlaintextActivation::forward(tensor);
        }

        CiphertextConvolve2D::CiphertextConvolve2D(CryptoData &CData, uint64_t scale, uint64_t scale_inv, uint32_t n_channels, uint32_t n_filters,
                                                   std::pair<uint32_t, uint32_t>& kernel_size,
                                                   std::pair<uint32_t, uint32_t>& stride, PADDING pad,
                                                   ACTIVATION activation)
                                                   : CiphertextActivation(CData, scale, scale_inv, activation), Cdata(CData), n_filters(n_filters),
                                                   n_channels(n_channels), kernel_size(kernel_size), stride(stride), pad(pad),bias(n_filters) {}

        void CiphertextConvolve2D::build_from_path(std::vector<std::string> &paths) {
            if (paths.size() < 2) {
                throw std::invalid_argument("Not enough paths to files to build layer");
            }

            auto* buffer = new int64_t[n_filters * kernel_size.first * kernel_size.second * n_channels];

            read_signed_matrix_from_csv(buffer, kernel_size.first * kernel_size.second * n_channels, n_filters , paths[0]);
            read_unsigned_vector_from_csv(bias.data(), n_filters, paths[1]);

            for(uint32_t i = 0; i < n_filters; i++) {
                auto start = buffer + i * kernel_size.first * kernel_size.second * n_channels;
                data.emplace_back(start, start + kernel_size.first * kernel_size.second * n_channels);
            }

            delete[] buffer;
        }

        std::shared_ptr<CiphertextTensor> CiphertextConvolve2D::forward(std::shared_ptr<CiphertextTensor>& input) {
            const std::shared_ptr<CiphertextTensor3D> tensor3D = std::dynamic_pointer_cast<CiphertextTensor3D>(input);

            uint32_t shapeX, shapeY, shapeZ;
            uint32_t output_y, output_x, padding_height, padding_width;
            uint32_t pad_t, pad_b, pad_l, pad_r;

            std::tie(shapeX, shapeY, shapeZ) = tensor3D->GetShape();

            // compute output parameters and padding
            if (this->pad == SAME) {
                output_y = std::ceil(double(shapeY) / this->stride.second);
                output_x = std::ceil(double(shapeX) / this->stride.first);
            } else {
                output_y = std::ceil(double(shapeY - kernel_size.second + 1) / this->stride.second);
                output_x = std::ceil(double(shapeX - kernel_size.first + 1) / this->stride.first);
            }

            if (shapeY % stride.second == 0) {
                padding_height = kernel_size.second > stride.second ? kernel_size.second - stride.second : 0;
            } else {
                padding_height = kernel_size.second > (stride.second % shapeY) ? kernel_size.second - (stride.second % shapeY) : 0;
            }

            if (shapeX % stride.first == 0) {
                padding_width = kernel_size.first > stride.first ? kernel_size.first - stride.first : 0;
            } else {
                padding_width = kernel_size.first > (stride.first % shapeX) ? kernel_size.first - (stride.first % shapeX) : 0;
            }

            pad_t = padding_height / 2;
            pad_b = padding_height - pad_t;

            pad_l = padding_width / 2;
            pad_r = padding_width - pad_l;

            // initialize output
            std::vector<std::vector<std::vector<CiphertextCRT>>> output(n_filters);
            for(uint32_t k = 0; k < n_filters; k++) {
                auto current_bias = bias[k];
                std::vector<std::vector<CiphertextCRT>> channel(output_y);
                for(uint32_t j = 0; j < output_y; j++) {
                    std::vector<CiphertextCRT> row;
                    for(uint32_t i = 0; i < output_x; i++) {
                        row.push_back(Cdata.EncryptCRT(current_bias, fbscrypto::CIPHERTEXT_STATE::TRIVIAL_BEFORE_KEYSWITCH));
                    }
                    channel[j] = std::move(row);
                }
                output[k] = std::move(channel);
            }

            // pad input data
            if (pad == SAME) {
                pad_ciphertext_tensor3d(Cdata, tensor3D, pad_t, pad_b, pad_l, pad_r);
            }

            for(uint32_t f_i = 0; f_i < n_filters; f_i++) {
                // get current filter
                auto& filter = data[f_i];
                auto& output_i = output[f_i];

                // go over each output "pixel"
#pragma omp parallel for collapse(2)
                for(uint32_t o_y = 0; o_y < output_y; o_y++) {
                    for(uint32_t o_x = 0; o_x < output_x; o_x++) {
                        CiphertextCRT output_yx = output_i[o_y][o_x];
                        // compute index in (padded) input
                        uint32_t i_x = o_x * stride.first;
                        uint32_t i_y = o_y * stride.second;

                        // do the convolution
                        for(uint32_t z = 0; z < n_channels; z++) {
                            for(uint32_t y = 0; y < kernel_size.second; y++) {
                                for(uint32_t x = 0; x < kernel_size.first; x++) {
                                    // filter index computation
                                    uint32_t filter_idx = x + y * kernel_size.first + z * kernel_size.second * kernel_size.first;
                                    auto& elem = (*tensor3D)[z][i_y + y][i_x + x];
                                    auto& f_elem = filter[filter_idx];
                                    output_yx += elem * f_elem;
                                }
                            }
                        }
                        output_i[o_y][o_x] = std::move(output_yx);
                    }
                }

            }

            std::shared_ptr<CiphertextTensor> tensor = std::make_shared<CiphertextTensor3D>(output);

            return CiphertextActivation::forward(tensor);
        }
    }
}