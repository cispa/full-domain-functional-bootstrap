//
// Created by leonard on 27.07.21.
//

#ifndef FBS_TENSOR_H
#define FBS_TENSOR_H

#include <vector>
#include <fbscontext.h>

#include "Utils.h"
#include "CRT.h"

namespace NN {

    // Refractor tensors so that only ONE copy of moduli is stored instead of ONE per element
    // EDIT: Nope, more work than uses
    template<typename IType>
    class TTensor {

    public:

        TTensor() = default;

        virtual const IType& at(std::vector<uint32_t> idx) = 0;

        virtual uint32_t GetDimensions() {
            return 0;
        };
    };

    template<typename IType>
    class TTensor1D : public TTensor<IType> {

    public:

        explicit TTensor1D() : TTensor<IType>(), shape(0) {}

        explicit TTensor1D(std::vector<IType>& values) : TTensor<IType>(), shape(values.size()), data(values) {}

        const IType& at(std::vector<uint32_t> idx) override {
            return data[idx[0]];
        }

        IType& operator[](uint32_t idx) {
            return data[idx];
        }

        void append(IType& new_end) {
            data.push_back(new_end);
            shape++;
        }

        void insert(uint32_t idx, IType& new_element) {
            data.insert(data.begin() + idx, new_element);
            shape++;
        }

        void append(std::vector<IType>& new_end) {
            data.insert(data.end(), new_end.begin(), new_end.end());
            shape = data.size();
        }

        void insert(uint32_t idx, std::vector<IType>& new_element) {
            data.insert(data.begin() + idx, new_element.begin(), new_element.end());
            shape = data.size();
        }

        uint32_t& GetShape() {
            return shape;
        }

        friend std::ostream& operator<<(std::ostream& stream, const TTensor1D<IType>& elem) {
            stream << "\t\t[ ";
            for(int i = 0; i < elem.data.size() - 1; i++) {
                stream << elem.data[i] << ", ";
            }
            stream << elem.data[elem.shape - 1] << " ]";
            return stream;
        }

        uint32_t GetDimensions() override {
            return 1;
        }

    private:

        uint32_t shape;
        std::vector<IType> data;

    };


    template<typename IType>
    class TTensor2D : public TTensor<IType> {
    public:
        explicit TTensor2D() : TTensor<IType>(), shapeX(0), shapeY(0) {}

        explicit TTensor2D(std::vector<std::vector<IType>>& values) : TTensor<IType>(), shapeX(values[0].size()), shapeY(values.size()) {
            for(auto& row : values) {
                data.emplace_back(row);
            }
        }

        const IType& at(std::vector<uint32_t> idx) override {
            return data[idx[1]][idx[0]];
        }

        TTensor1D<IType>& operator[](uint32_t idx) {
            return data[idx];
        }

        std::pair<uint32_t, uint32_t> GetShape() {
            return std::make_pair(shapeX, shapeY);
        }

        void insert(uint32_t idx, TTensor1D<IType>& new_member) {
            auto shape = new_member.GetShape();
            if (shape != shapeX) {
                throw std::invalid_argument("Inserted Member must have same shape as other members");
            }

            data.insert(data.begin() + idx, new_member);
            shapeY++;
        }

        void insert(uint32_t idx, std::vector<TTensor1D<IType>>& new_members) {
            auto shape = new_members[0].GetShape();
            if (shape != shapeX) {
                throw std::invalid_argument("Inserted Member must have same shape as other members");
            }

            data.insert(data.begin() + idx, new_members.begin(), new_members.end());
            shapeY += new_members.size();
        }

        void append(TTensor1D<IType> new_member) {
            auto shape = new_member.GetShape();
            if (shape != shapeX) {
                throw std::invalid_argument("Inserted Member must have same shape as other members");
            }

            data.push_back(new_member);
            shapeY++;
        }

        void append(std::vector<TTensor1D<IType>>& new_members) {
            auto shape = new_members[0].GetShape();
            if (shape != shapeX) {
                throw std::invalid_argument("Inserted Member must have same shape as other members");
            }

            data.insert(data.end(), new_members.begin(), new_members.end());
            shapeY += new_members.size();
        }

        uint32_t& GetShapeX() { return shapeX; }

        uint32_t& GetShapeY() {return shapeY; }

        void PropagateShapeChange() {
            for(auto& elem : data) {
                elem.GetShape() = shapeX;
            }
        }

        friend std::ostream& operator<<(std::ostream& stream, const TTensor2D<IType>& tensor) {
            stream << "\t[" << std::endl;
            for(auto& elem : tensor.data)
                stream << elem << std::endl;
            stream << "\t]";
            return stream;
        }

        uint32_t GetDimensions() override {
            return 2;
        }

    private:

        uint32_t shapeX, shapeY;
        std::vector<TTensor1D<IType>> data;

    };

    template<typename IType>
    class TTensor3D : public TTensor<IType> {
    public:
        explicit TTensor3D() : TTensor<IType>(), shapeX(0), shapeY(0), shapeZ(0) {}

        explicit TTensor3D(std::vector<std::vector<std::vector<IType> >>& values ) : TTensor<IType>(), shapeZ(values.size()), shapeY(values[0].size()), shapeX(values[0][0].size()) {
            for(auto& block : values) {
                data.emplace_back(block);
            }
        }

        const IType& at(std::vector<uint32_t> idx) override {
            return data[idx[2]][idx[1]][idx[0]];
        }

        TTensor2D<IType>& operator[](uint32_t idx) {
            return data[idx];
        }

        std::tuple<uint32_t, uint32_t, uint32_t> GetShape() {
            return std::make_tuple(shapeX, shapeY, shapeZ);
        }

        void insert(uint32_t idx, TTensor2D<IType> new_member) {
            auto shape = new_member.GetShape();
            if (shape.first != shapeX || shape.second != shapeY) {
                throw std::invalid_argument("Inserted member must have same shape as other members !");
            }

            data.insert(idx, new_member);
            shapeZ++;
        }

        void insert(uint32_t idx, std::vector<TTensor2D<IType>>& new_members) {
            auto shape = new_members[0].GetShape();
            if (shape.first != shapeX || shape.second != shapeY) {
                throw std::invalid_argument("Inserted Member must have same shape as other members");
            }

            data.insert(data.begin() + idx, new_members.begin(), new_members.end());
            shapeY += new_members.size();
        }

        void append(uint32_t idx, TTensor2D<IType> new_member) {
            auto shape = new_member.GetShape();
            if (shape.first != shapeX || shape.second != shapeY) {
                throw std::invalid_argument("Inserted member must have same shape as other members !");
            }

            data.push_back(new_member);
            shapeZ++;
        }

        void append(std::vector<TTensor2D<IType>>& new_members) {
            auto shape = new_members[0].GetShape();
            if (shape.first != shapeX || shape.second != shapeY) {
                throw std::invalid_argument("Inserted Member must have same shape as other members");
            }

            data.insert(data.end(), new_members.begin(), new_members.end());
            shapeY += new_members.size();
        }

        uint32_t& GetShapeX() {
            return shapeX;
        };

        uint32_t& GetShapeY() {
            return shapeY;
        }

        uint32_t& GetShapeZ() {
            return shapeZ;
        }

        void PropagateShapeChange() {
            for(auto& elem : data) {
                elem.GetShapeX() = shapeX;
                elem.GetShapeY() = shapeY;
            }
        }

        friend std::ostream& operator<<(std::ostream& stream, const TTensor3D<IType>& tensor) {
            stream << "[" << std::endl;
            for(auto& elem : tensor.data)
                stream << elem << std::endl;
            stream << "]" << std::endl;
            return stream;
        }

        uint32_t GetDimensions() override {
            return 3;
        }


    private:

        uint32_t shapeX, shapeY, shapeZ;
        std::vector<TTensor2D<IType>> data;

    };



    using PlaintextTensor = TTensor<PlaintextCRT>;
    using CiphertextTensor = TTensor<CiphertextCRT>;

    using PlaintextTensor1D = TTensor1D<PlaintextCRT>;
    using CiphertextTensor1D = TTensor1D<CiphertextCRT>;

    using PlaintextTensor2D = TTensor2D<PlaintextCRT>;
    using CiphertextTensor2D = TTensor2D<CiphertextCRT>;

    using PlaintextTensor3D = TTensor3D<PlaintextCRT>;
    using CiphertextTensor3D = TTensor3D<CiphertextCRT>;

    void pad_plaintext_tensor3d(std::vector<uint64_t>&, const std::shared_ptr<PlaintextTensor3D>&,
            uint32_t pad_t, uint32_t pad_b, uint32_t pad_l, uint32_t pad_r);

    void pad_ciphertext_tensor3d(CryptoData& data, const std::shared_ptr<CiphertextTensor3D>&,
                                uint32_t pad_t, uint32_t pad_b, uint32_t pad_l, uint32_t pad_r);

    template<typename TensorType>
    std::shared_ptr<TTensor3D<TensorType>> move_channels_backward(std::shared_ptr<TTensor3D<TensorType>>& tensor3D) {
        uint32_t s_z, s_y, s_x;
        std::tie(s_x, s_y, s_z) = tensor3D->GetShape();

        std::vector<std::vector<std::vector<TensorType>>> result_vec(s_y);
        for(uint32_t j = 0; j < s_y; j++) {
            std::vector<std::vector<TensorType>> y_vec(s_x);
            for(uint32_t k = 0; k < s_x; k++) {
                std::vector<TensorType> x_vec;
                for(uint32_t i = 0; i < s_z; i++) {
                    x_vec.push_back((*tensor3D)[i][j][k]);
                }
                y_vec[k] = std::move(x_vec);
            }
            result_vec[j] = std::move(y_vec);
        }

        return std::make_shared<TTensor3D<TensorType>>(result_vec);
    }
}

#endif //FBS_TENSOR_H
