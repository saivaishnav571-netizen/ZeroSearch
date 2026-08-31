#include "entropy.h"

#include <cmath>
#include <unordered_map>

namespace zerotrace {

double calculate_entropy(const std::string& text) {

    if (text.empty()) {
        return 0.0;
    }

    std::unordered_map<char, int> frequencies;

    for (char character : text) {
        ++frequencies[character];
    }

    double entropy = 0.0;

    const double length =
        static_cast<double>(text.length());

    for (const auto& entry : frequencies) {

        const double probability =
            static_cast<double>(entry.second) / length;

        entropy -= probability * std::log2(probability);
    }

    return entropy;
}

}