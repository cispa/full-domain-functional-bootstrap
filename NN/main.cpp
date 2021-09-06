//
// Created by leonard on 27.07.21.
//

#include <omp.h>
#include "Utils.h"
#include "PrebuildNetworks.h"

#define TICK std::chrono::high_resolution_clock::now();

using namespace NN;


int main() {

    std::cout << std::endl << "### RUNNING NEURAL NETWORK EVALUATION ###" << std::endl;
    std::cout << "## TESTING MNIST 1 ##" << std::endl;

    for(uint32_t m = 6; m <= 11; m++) {
        std::cout << "[Using modulus = " << ((1 << m)) << "]" << std::endl;
        for(uint32_t i = 0; i < 6; i++) {
            run_mnist_1_encrypted("nn_data/MNIST_1_6", 1 << m, i);
        }
    }

    std::cout << "## TESTING MNIST 2 ##" << std::endl;
    for(uint32_t m = 6; m <= 11; m++) {
        std::cout << "[Using modulus = " << ((1 << m)) << "]" << std::endl;
        for(uint32_t i = 0; i < 6; i++) {
            run_mnist_2_encrypted("nn_data/MNIST_2_4_T1", 1 << m, i);
        }
    }


}
