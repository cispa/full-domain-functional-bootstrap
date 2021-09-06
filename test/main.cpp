#include <iostream>
#include "implementation.h"
#include "functions.h"
#include "setup.h"
#include "LUT.h"
#include "error.h"

int main() {

    std::cout << "### TIMING FDBFB PARAMETER SETS ###"  << std::endl;

    for(uint32_t i = 0; i < 6; i++) {
        time_parameter_set(fbscrypto::FBSFHEPARAMSET_LIST[i], fbscrypto::FBSFHEPARAMSET_NAMES[i]);
    }

    std::cout << "### TIMING BINARY PARAMETER SETS ###" << std::endl;

    for(uint32_t i = 6; i < 9; i++) {
        time_binary_parameter_set(fbscrypto::FBSFHEPARAMSET_LIST[i], fbscrypto::FBSFHEPARAMSET_NAMES[i]);
    }

    std::cout << std::endl << "### TIMING ADDITION AND SCALAR MULTIPLICATION ###" << std::endl;

    benchmark_functions();

    std::cout << std::endl << "### TIMING LUT EVALUATION FOR DIFFERENT BIT SIZE ###" << std::endl;

    std::vector<uint32_t> bits = {2 * 6, 2 * 7, 2 * 8, 2 * 9, 2 * 10, 2 * 11};

    run_lut_tests(bits);


}
