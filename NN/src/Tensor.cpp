//
// Created by leonard on 07.08.21.
//

#include "Tensor.h"

namespace NN {

    void pad_plaintext_tensor3d(std::vector<uint64_t> & moduli, const std::shared_ptr<PlaintextTensor3D>& in, uint32_t pad_t,
                                    uint32_t pad_b, uint32_t pad_l, uint32_t pad_r) {
        uint32_t shapeX, shapeY, shapeZ;
        std::tie(shapeX, shapeY, shapeZ) = in->GetShape();

        // create nil elements
        std::vector<PlaintextCRT> padding_top_bottom;
        std::vector<PlaintextCRT> padding_left, padding_right;

        // top and bottom pad
        for(uint32_t j = 0; j < shapeX + pad_l + pad_r; j++) {
            padding_top_bottom.emplace_back(0, moduli);
        }

        // side padding
        for(uint32_t p_i = 0; p_i < pad_l; p_i++) {
            padding_left.emplace_back(0, moduli);
        }

        for(uint32_t p_i = 0; p_i < pad_r; p_i++) {
            padding_right.emplace_back(0, moduli);
        }

        PlaintextTensor1D top_tensor(padding_top_bottom);

        for(uint32_t i = 0; i < shapeZ; i++) {
            auto& current_channel = (*in)[i];

            for(uint32_t j = 0; j < shapeY; j++) {
                current_channel[j].insert(0, padding_left);
                current_channel[j].append(padding_right);
            }

            current_channel.GetShapeX() += pad_r + pad_l;

            // TODO: Use the functions I created for that...
            for(uint32_t p_i = 0; p_i < pad_t; p_i++) {
                current_channel.insert(0, top_tensor);
            }

            for(uint32_t p_i = 0; p_i < pad_b; p_i++) {
                current_channel.append(top_tensor);
            }
        }

        in->GetShapeY() += pad_t + pad_b;
        in->GetShapeX() += pad_l + pad_r;
        in->PropagateShapeChange();
    }

    void pad_ciphertext_tensor3d(CryptoData& data, const std::shared_ptr<CiphertextTensor3D>& in,
                                 uint32_t pad_t, uint32_t pad_b, uint32_t pad_l, uint32_t pad_r) {

        auto moduli = data.GetModuli();

        uint32_t shapeX, shapeY, shapeZ;
        std::tie(shapeX, shapeY, shapeZ) = in->GetShape();

        // create nil elements
        std::vector<CiphertextCRT> padding_top_bottom;
        std::vector<CiphertextCRT> padding_left, padding_right;

        auto zero = data.EncryptCRT(0);
        // top and bottom pad
        for(uint32_t j = 0; j < shapeX + pad_l + pad_r; j++) {
            padding_top_bottom.push_back(zero);
        }

        // side padding
        for(uint32_t p_i = 0; p_i < pad_l; p_i++) {
            padding_left.push_back(zero);
        }

        for(uint32_t p_i = 0; p_i < pad_r; p_i++) {
            padding_right.push_back(zero);
        }

        CiphertextTensor1D top_tensor(padding_top_bottom);

        for(uint32_t i = 0; i < shapeZ; i++) {
            auto& current_channel = (*in)[i];

            for(uint32_t j = 0; j < shapeY; j++) {
                current_channel[j].insert(0, padding_left);
                current_channel[j].append(padding_right);
            }

            current_channel.GetShapeX() += pad_r + pad_l;

            // TODO: Use the functions I created for that...
            for(uint32_t p_i = 0; p_i < pad_t; p_i++) {
                current_channel.insert(0, top_tensor);
            }

            for(uint32_t p_i = 0; p_i < pad_b; p_i++) {
                current_channel.append(top_tensor);
            }
        }

        in->GetShapeY() += pad_t + pad_b;
        in->GetShapeX() += pad_l + pad_r;
        in->PropagateShapeChange();
    }
}