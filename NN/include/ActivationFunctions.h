//
// Created by leonard on 08.08.21.
//

#ifndef FBS_ACTIVATIONFUNCTIONS_H
#define FBS_ACTIVATIONFUNCTIONS_H

#include <cstdint>
#include <cmath>

#include "Utils.h"

namespace NN {

    static uint32_t relu_degree = 0;
    static long double relu_coef[] = {0};

    static uint32_t tanh_degree = 0;
    static long double tanh_coef[] = {0.};

    static uint32_t id_degree = 1;
    static long double id_coef[] = {0, 1.};

    static uint32_t sigmoid_degree = 0;
    static long double sigmoid_coef[] = {0};

    template<typename T>
    inline std::vector<long double> SOFTMAX(std::vector<T> input) {
        std::vector<long double> conv(input.begin(), input.end());
        std::vector<long double> raised(input.size());
        std::vector<long double> result(input.size());

        std::transform(conv.begin(), conv.end(), conv.begin(), [](long double in) {return std::exp(in);});
        auto sum = std::accumulate(conv.begin(), conv.end(), (long double)0.);

        std::transform(raised.begin(), raised.end(), result.begin(), [sum](long double in) { return in / sum; } );

        return result;
    }

    template<typename T>
    inline T RELU(T input, T cutoff) {
        if(input >= cutoff)
            return T(0);
        else
            return input;
    }

    template<typename T>
    inline T TANH(T input) {
        long double conv = input;
        return T(tanhl(conv));
    }

    template<typename T>
    inline T SIGMOID(T input) {
        long double conv = input;
        return T(1. / (1. + std::exp(-conv)));
    }

    template<typename T>
    inline T RELU_POLY(T input) {
        long double conv = input;
        return evaluate_horner(conv, relu_coef, relu_degree);
    }

    template<typename T>
    inline T TANH_POLY(T input) {
        long double conv = input;
        return evaluate_horner(conv, tanh_coef, tanh_degree);
    }

    template<typename T>
    inline T SIGMOID_POLY(T input) {
        long double conv = input;
        return evaluate_horner(conv, sigmoid_coef, sigmoid_degree);
    }
}

#endif //FBS_ACTIVATIONFUNCTIONS_H
