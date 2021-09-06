//
// Created by leonard on 08.08.21.
//

#include "PrebuildNetworks.h"
#include "Dataset.h"

#define TICK std::chrono::high_resolution_clock::now()

namespace NN {

    void run_mnist_1_plain(std::string path, uint64_t modulus, uint32_t n) {

        std::vector<uint64_t> moduli = {modulus};

        if (path[path.size() - 1] != '/')
            path.append("/");

        auto mnist_images_path = path + "dataset/mnist_100_images.csv";
        auto mnist_labels_path = path + "dataset/mnist_100_labels.csv";

        // import images
        auto mnist_images = read_plain_mnist100_1d(moduli, mnist_images_path);
        auto mnist_labels = read_mnist100_labels(mnist_labels_path);

        PlaintextNetwork nn(moduli);
        nn.build_from_directory(path);

        auto start = TICK;

        std::vector<uint64_t> results;

        for(uint32_t j = 0; j < n; j++) {

            auto& img = mnist_images[j];
            std::shared_ptr<PlaintextTensor> tensor = img;
            auto result = nn.run(tensor);
            for(uint32_t i = 0; i < 10; i++) {
                auto elem = result->at({i});
                if (elem.at(0) == 1ull) {
                    results.push_back(i);
                    break;
                }
            }
        }

        auto stop = TICK;

        double correct_count = 0;
        for(uint32_t i = 0; i < n; i++) {
            if (results[i] == mnist_labels[i])
                correct_count += 1;
        }
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(stop-start).count();

        std::cout << "[PLAINTEXT] Evaluation accuracy is " << correct_count / n << " " << std::endl;
        std::cout << "The evaluation of" << n << "samples took " << elapsed << "seconds" << std::endl;
    }

    void run_mnist_1_encrypted(std::string path, uint64_t modulus, uint32_t paramset_idx, uint32_t n) {

        std::vector<uint64_t> moduli = {modulus};

        CryptoData data(fbscrypto::FBSFHEPARAMSET_LIST[paramset_idx], moduli);

        if (path[path.size() - 1] != '/')
            path.append("/");

        auto mnist_images_path = path + "dataset/mnist_100_images.csv";
        auto mnist_labels_path = path + "dataset/mnist_100_labels.csv";

        // import images
        auto mnist_images = read_encrypted_mnist100_1d(data, mnist_images_path);
        auto mnist_labels = read_mnist100_labels(mnist_labels_path);

        CiphertextNetwork nn(data);
        nn.build_from_directory(path);

        auto start = TICK;

        std::vector<uint64_t> results(n);

        for(uint32_t ctr = 0; ctr < n; ctr++) {
            std::shared_ptr<CiphertextTensor> tensor = mnist_images[ctr];
            auto result = nn.run(tensor);
            for(uint32_t i = 0; i < 10; i++) {
                auto enc_elem = result->at({i});
                auto elem = data.DecryptCRT(enc_elem);
                if (elem.at(0) >= 1ull) {
                    results[ctr] = i;
                    break;
                }
            }
        }

        auto stop = TICK;

        double correct_count = 0;
        for(uint32_t i = 0; i < n; i++) {
            if (results[i] == mnist_labels[i])
                correct_count += 1;
        }
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(stop-start).count();

        std::cout << "[" << fbscrypto::FBSFHEPARAMSET_NAMES[paramset_idx] << "]" << " Accuracy is " << correct_count / n << " " << std::endl;
        std::cout << "The evaluation of " << n <<  " samples took " << elapsed << "seconds" << std::endl << std::endl;
    }

    void run_mnist_2_encrypted(std::string path, uint64_t modulus, uint32_t paramset_idx, uint32_t n) {

        std::vector<uint64_t> moduli = {modulus};

        CryptoData data(fbscrypto::FBSFHEPARAMSET_LIST[paramset_idx], moduli);

        if (path[path.size() - 1] != '/')
            path.append("/");

        auto mnist_images_path = path + "dataset/mnist_100_images.csv";
        auto mnist_labels_path = path + "dataset/mnist_100_labels.csv";

        // import images
        auto mnist_images = read_encrypted_mnist100_3d(data, mnist_images_path);
        auto mnist_labels = read_mnist100_labels(mnist_labels_path);

        CiphertextNetwork nn(data);
        nn.build_from_directory(path);

        auto start = TICK;

        std::vector<uint64_t> results(n);

        for(uint32_t ctr = 0; ctr < n; ctr++) {
            std::shared_ptr<CiphertextTensor> tensor = mnist_images[ctr];
            auto result = nn.run(tensor);
            auto now = std::chrono::system_clock::now();
            auto now_time = std::chrono::system_clock::to_time_t(now);
            std::cout << "Finished iteration " << ctr << " at " << std::ctime(&now_time) << std::endl;
            for(uint32_t i = 0; i < 10; i++) {
                auto enc_elem = result->at({i});
                auto elem = data.DecryptCRT(enc_elem);
                if (elem.at(0) >= 1ull) {
                    results[ctr] = i;
                    break;
                }
            }
        }

        auto stop = TICK;

        double correct_count = 0;
        for(uint32_t i = 0; i < n; i++) {
            if (results[i] == mnist_labels[i])
                correct_count += 1;
        }
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(stop-start).count();

        std::cout << "[" << fbscrypto::FBSFHEPARAMSET_NAMES[paramset_idx] << "]" << " Accuracy is " << correct_count / n << " " << std::endl;
        std::cout << "The evaluation of " << n <<  " samples took " << elapsed << "seconds" << std::endl << std::endl;
    }

    void run_mnist_2_plain(std::string path, uint64_t modulus, uint32_t n) {

        std::vector<uint64_t> moduli = {modulus};

        if (path[path.size() - 1] != '/')
            path.append("/");

        auto mnist_images_path = path + "dataset/mnist_100_images.csv";
        auto mnist_labels_path = path + "dataset/mnist_100_labels.csv";

        // import images
        auto mnist_images = read_plain_mnist100_3d(moduli, mnist_images_path);
        auto mnist_labels = read_mnist100_labels(mnist_labels_path);

        PlaintextNetwork nn(moduli);
        nn.build_from_directory(path);

        auto start = TICK;

        std::vector<uint64_t> results;
        for(uint32_t j = 0; j < n; j++) {
            std::shared_ptr<PlaintextTensor> tensor = mnist_images[j];
            auto result = nn.run(tensor);
            for(uint32_t i = 0; i < 10; i++) {
                auto elem = result->at({i});
                if (elem.at(0) == 1ull) {
                    results.push_back(i);
                    break;
                }
            }
        }

        auto stop = TICK;

        double correct_count = 0;
        for(uint32_t i = 0; i < n; i++) {
            if (results[i] == mnist_labels[i])
                correct_count += 1;
        }
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(stop-start).count();

        std::cout << "Plaintext evaluation accuracy is " << correct_count / n << " % " << std::endl;
        std::cout << "The evaluation of 100 samples took " << elapsed << " seconds" << std::endl;
    }


}