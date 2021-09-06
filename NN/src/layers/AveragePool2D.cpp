//
// Created by leonard on 07.08.21.
//

#include <utility>

#include "layers/AveragePool2D.h"

namespace NN {
    namespace Layers {

        inline bool is_outside_box(uint32_t i, uint32_t j, uint32_t tl_i, uint32_t tl_j, uint32_t br_i, uint32_t br_j) {
            return (i < tl_i) || (i >= br_i) || (j < tl_j) || (j >= br_j);
        }

        PlaintextAveragePool2D::PlaintextAveragePool2D(std::vector<uint64_t> &moduli, uint64_t scale, uint64_t scale_inv,
                                                       std::pair<uint32_t, uint32_t>& pool_size,
                                                       std::pair<uint32_t, uint32_t>& stride, PADDING pad)
                                                       : PlaintextLayer(moduli, scale, scale_inv), pool_size(std::move(pool_size)), stride(stride), pad(pad) {

        }

        void PlaintextAveragePool2D::build_from_path(std::vector<std::string> &paths) {
            throw std::runtime_error("There is no need to read any data for an average pool.");
        }

        std::shared_ptr<PlaintextTensor> PlaintextAveragePool2D::forward(std::shared_ptr<PlaintextTensor> &input) {

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
                output_y = std::ceil(double(shapeY - pool_size.second + 1) / this->stride.second);
                output_x = std::ceil(double(shapeX - pool_size.first + 1) / this->stride.first);
            }

            if (shapeY % stride.second == 0) {
                padding_height = pool_size.second > stride.second ? pool_size.second - stride.second : 0;
            } else {
                padding_height = pool_size.second > (stride.second % shapeY) ? pool_size.second - (stride.second % shapeY) : 0;
            }

            if (shapeX % stride.first == 0) {
                padding_width = pool_size.first > stride.first ? pool_size.first - stride.first : 0;
            } else {
                padding_width = pool_size.first > (stride.first % shapeX) ? pool_size.first - (stride.first % shapeX) : 0;
            }

            pad_t = padding_height / 2;
            pad_b = padding_height - pad_t;

            pad_l = padding_width / 2;
            pad_r = padding_width - pad_l;

            if (pad == SAME)
                pad_plaintext_tensor3d(this->moduli, tensor3D, pad_t, pad_b, pad_l, pad_r);

            double garbage;
            std::vector<std::vector<std::vector<PlaintextCRT>>> output(shapeZ);
            for(uint32_t c_i = 0; c_i < shapeZ; c_i++) {
                std::vector<std::vector<PlaintextCRT>> output_channel(output_y);
                auto& input_channel = (*tensor3D)[c_i];
                for(uint32_t o_j = 0; o_j < output_y; o_j++) {
                    std::vector<PlaintextCRT> row;
                    for(uint32_t o_i = 0; o_i < output_x; o_i++) {
                        row.emplace_back(0, this->moduli);
                        uint32_t div_coef = pool_size.first * pool_size.second;

                        uint32_t in_i = o_i * stride.first;
                        uint32_t in_j = o_j * stride.second;

                        for(uint32_t p_i = 0; p_i < pool_size.first; p_i++) {
                            for(uint32_t p_j = 0; p_j < pool_size.second; p_j++) {
                                uint32_t read_i = in_i + p_i;
                                uint32_t read_j = in_j + p_j;

                                if (is_outside_box(read_i, read_j, pad_l, pad_t, pad_l + shapeX, pad_t + shapeY)) {
                                    div_coef--;
                                    continue;
                                }

                                row[o_i] += input_channel[read_j][read_i];
                            }
                        }
                        if (scale_inverse == 0) {
                            auto contents = row[o_i].GetContents();
                            for(uint32_t i = 0; i < this->moduli.size(); i++) {
                                double tmp = contents[i];
                                if (tmp >= (this->moduli[i] / 2))
                                    tmp -= this->moduli[i];

                                tmp /= div_coef;
                                auto coef = std::roundl((std::modf(tmp, &garbage)) > 0.5 ? std::ceil(tmp) : std::floor(tmp));
                                if (coef < 0)
                                    coef += this->moduli[i];
                                contents[i] = uint64_t(coef);
                            }
                            for(auto& coef : row[o_i].GetContents()) {

                                double tmp = double(coef) / div_coef;
                                coef = std::roundl((std::modf(tmp, &garbage)) > 0.5 ? std::ceil(tmp) : std::floor(tmp));
                            }
                        } else {
                            auto& contents = row[o_i].GetContents();
                            for(uint32_t i = 0; i < this->moduli.size(); i++) {

                                uint64_t tmp = (contents[i] * scale_inverse ) % this->moduli[i];
                                int64_t tmp_s;

                                if (tmp >= (this->moduli[i] / 2))
                                    tmp_s = int64_t(tmp) - int64_t(this->moduli[i]);
                                else
                                    tmp_s = int64_t(tmp);

                                long double res = (long double)(tmp_s) / div_coef;

                                auto tmp_d = std::roundl((std::modf(res, &garbage)) > 0.5 ? std::ceil(res) : std::floor(res));
                                if (tmp_d < 0)
                                    tmp_d += this->moduli[i];
                                contents[i] = (uint64_t(tmp_d) * scale) % this->moduli[i];
                            }
                        }
                    }
                    output_channel[o_j] = std::move(row);
                }
                output[c_i] = std::move(output_channel);
            }

            return std::make_shared<PlaintextTensor3D>(output);
        }

        CiphertextAveragePool2D::CiphertextAveragePool2D(CryptoData &data, uint64_t scale, uint64_t scale_inv,
                                                         std::pair<uint32_t, uint32_t> pool_size,
                                                         std::pair<uint32_t, uint32_t> stride, PADDING pad)
                                                         : CiphertextLayer(data.GetModuli(), scale, scale_inv),
                                                         data(data), pool_size(pool_size), stride(stride), pad(pad){

        }

        void CiphertextAveragePool2D::build_from_path(std::vector<std::string> &paths) {

        }

        std::shared_ptr<CiphertextTensor> CiphertextAveragePool2D::forward(std::shared_ptr<CiphertextTensor> &input) {
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
                output_y = std::ceil(double(shapeY - pool_size.second + 1) / this->stride.second);
                output_x = std::ceil(double(shapeX - pool_size.first + 1) / this->stride.first);
            }

            if (shapeY % stride.second == 0) {
                padding_height = pool_size.second > stride.second ? pool_size.second - stride.second : 0;
            } else {
                padding_height = pool_size.second > (stride.second % shapeY) ? pool_size.second - (stride.second % shapeY) : 0;
            }

            if (shapeX % stride.first == 0) {
                padding_width = pool_size.first > stride.first ? pool_size.first - stride.first : 0;
            } else {
                padding_width = pool_size.first > (stride.first % shapeX) ? pool_size.first - (stride.first % shapeX) : 0;
            }

            pad_t = padding_height / 2;
            pad_b = padding_height - pad_t;

            pad_l = padding_width / 2;
            pad_r = padding_width - pad_l;

            if (pad == SAME)
                pad_ciphertext_tensor3d(this->data, tensor3D, pad_t, pad_b, pad_l, pad_r);

            double garbage;
            std::vector<std::vector<std::vector<CiphertextCRT>>> output(shapeZ);
#pragma omp parallel for
            for(uint32_t c_i = 0; c_i < shapeZ; c_i++) {
                std::vector<std::vector<CiphertextCRT>> output_channel(output_y);
                auto& input_channel = (*tensor3D)[c_i];
                for(uint32_t o_j = 0; o_j < output_y; o_j++) {
                    std::vector<CiphertextCRT> row;
                    for(uint32_t o_i = 0; o_i < output_x; o_i++) {
                        row.emplace_back(data.EncryptCRT(0));
                        uint32_t div_coef = pool_size.first * pool_size.second;

                        uint32_t in_i = o_i * stride.first;
                        uint32_t in_j = o_j * stride.second;

                        for(uint32_t p_i = 0; p_i < pool_size.first; p_i++) {
                            for(uint32_t p_j = 0; p_j < pool_size.second; p_j++) {
                                uint32_t read_i = in_i + p_i;
                                uint32_t read_j = in_j + p_j;

                                if (is_outside_box(read_i, read_j, pad_l, pad_t, pad_l + shapeX, pad_t + shapeY)) {
                                    div_coef--;
                                    continue;
                                }

                                row[o_i] += input_channel[read_j][read_i];
                            }
                        }
                        std::vector<fbscrypto::BootstrapFunction> bstF;
                        for(auto& modulus: this->moduli) {
                            bstF.emplace_back([modulus, div_coef](uint64_t a) {
                                int64_t m = a > (modulus / 2) ? int64_t(a) - int64_t(modulus) : int64_t(a);
                                double r = double(m) / div_coef;
                                if (r < 0) {
                                    return uint64_t(std::round(r + int64_t(modulus)));
                                } else {
                                    return uint64_t(std::round(r));
                                }
                            }, modulus);
                        }
                        auto tmp = data.DoKeySwitch(row[o_i]);
                        row[o_i] = data.BootstrapCRT(tmp, bstF,  fbscrypto::SKIP_STEP::KEYSWITCH);
                    }
                    output_channel[o_j] = std::move(row);
                }
                output[c_i] = std::move(output_channel);
            }

            return std::make_shared<CiphertextTensor3D>(output);

        }

        // TODO Ciperhtext equivalent
    }
}
