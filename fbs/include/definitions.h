//
// Created by leonard on 06.05.21.
//

#ifndef FBS_DEFINITIONS_H
#define FBS_DEFINITIONS_H

#include <cstdint>
#include <functional>
#include <utility>
#include <chrono>

/* Macros to measure time, for benchmarking */
#ifdef MEASURE_TIME

#define TIME_SECTION_MILLIS(Y, X)  \
auto start = std::chrono::high_resolution_clock::now(); \
X;                          \
auto stop = std::chrono::high_resolution_clock::now();  \
auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(stop-start); \
std::cerr << "Section " #Y << " took " << elapsed.count() << "ms." << std::endl;


#define TIME_SECTION_MICRO(Y, X) {\
auto start = std::chrono::high_resolution_clock::now(); \
X                          \
auto stop = std::chrono::high_resolution_clock::now();  \
auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(stop-start); \
std::cerr << "Section " #Y << " took " << elapsed.count() << "ms." << std::endl;  \
}

#else

#define TIME_SECTION_MILLIS(Y, X) X
#define TIME_SECTION_MICRO(Y, X) X

#endif


namespace fbscrypto {

    /**
     * Wrapper struct for functions to be computed during bootstrap
     */
    struct BootstrapFunction {
    public:

        /**
         * Constructor for wrapper
         * @param a_map lambda/anonymous function for the actual function
         * @param message_space used message space, required since the chunksize of the rotation polynomial depends on the function
         */
        BootstrapFunction(std::function<uint32_t(uint32_t)> a_map, uint32_t message_space) : map(std::move(a_map)), message_space(message_space) {}

        /**
         * Calls the underlying function
         * @param a argument
         * @return map(a)
         */
        uint32_t operator()(uint32_t a) const {
            return map(a);
        }

        /**
         * Returns the message space which the function uses;
         * @return message_space
         */
        uint32_t GetMessageSpace() const {return message_space;}

    private:

        std::function<uint32_t(uint32_t)> map;
        uint32_t message_space;

    };

}



#endif //FBS_DEFINITIONS_H
