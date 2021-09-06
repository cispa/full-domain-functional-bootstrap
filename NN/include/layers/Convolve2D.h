//
// Created by Leonard on 8/4/21.
//

#ifndef FBS_CONVOLVE2D_H
#define FBS_CONVOLVE2D_H

#include "Layer.h"
#include "Utils.h"
#include "Activation.h"

namespace NN {
    // TODO: BasicActivation for N-D inputs

    /*
     * How conv layers should be exported
     * using layer.get_weight() will yield a tensor of shape [m,n,o,p]
     * where an entry [i,j,k,l] is coefficient [i,j,k] of the l-th filter.
     *
     * Exporting a layer shall yield two files
     *
     * 1] a file containing the biases:
     *      Line I of the file will contain the bias of filter I
     * 2] a file containing the filters:
     *      Line I of the file will contain the vector stored in the filter at index [i,j,k] such that
     *      I = k + j * o + i * o * m. In practice this means we can dump the filters using the following pseudocode
     *      for i in range(m):
     *          for j in range(n):
     *              for k in range(o):
     *                  file.writeline(layer.get_weight()[i,j,k]
     */

    namespace Layers {


        class PlaintextConvolve2D : public PlaintextActivation {

        public:
            PlaintextConvolve2D(std::vector<uint64_t> &moduli, uint64_t scale, uint64_t scale_inv, uint32_t n_channels, uint32_t n_filters,
                                std::pair<uint32_t, uint32_t> &kernel_size, std::pair<uint32_t, uint32_t> &stride,
                                PADDING pad, ACTIVATION activation);

            std::shared_ptr<PlaintextTensor> forward(std::shared_ptr<PlaintextTensor>& input) override;

            void build_from_path(std::vector<std::string>& paths) override;

        private:

            uint32_t n_filters, n_channels;
            std::vector<uint64_t> bias;
            std::vector<std::vector<int64_t>> data;
            PADDING pad;
            std::pair<uint32_t, uint32_t> kernel_size, stride;

        };

        class CiphertextConvolve2D : public CiphertextActivation {
        public:
            CiphertextConvolve2D(CryptoData& CData, uint64_t scale, uint64_t scale_inv, uint32_t n_channels, uint32_t n_filters, std::pair<uint32_t,
                                 uint32_t>& kernel_size, std::pair<uint32_t,uint32_t>& stride, PADDING pad,
                                 ACTIVATION activation);

            std::shared_ptr<CiphertextTensor> forward(std::shared_ptr<CiphertextTensor>& input) override;

            void build_from_path(std::vector<std::string>& path) override;

        private:

            CryptoData& Cdata;

            uint32_t n_filters, n_channels;
            std::vector<uint64_t> bias;
            std::vector<std::vector<int64_t>> data;
            PADDING pad;
            std::pair<uint32_t, uint32_t> kernel_size, stride;

        };
    }
}

#endif //FBS_CONVOLVE2D_H
