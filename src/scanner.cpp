#include "scanner.h"

#include <filesystem>

namespace zerotrace {

std::vector<std::string> scan_directory(const std::string& path) {

    std::vector<std::string> files;

    for (const auto& entry : std::filesystem::recursive_directory_iterator(path)) {

        if (entry.is_regular_file()) {
            files.push_back(entry.path().string());
        }
    }

    return files;
}

}