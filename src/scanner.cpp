#include "scanner.h"

#include <filesystem>
#include <unordered_set>

namespace zerotrace {

bool should_scan_file(const std::string& path) {

    const std::filesystem::path file_path(path);

    const std::string filename = file_path.filename().string();
    const std::string extension = file_path.extension().string();

    if (filename == ".env" ||
        filename == "Dockerfile" ||
        filename == "Makefile") {
        return true;
    }

    const std::unordered_set<std::string> allowed_extensions = {
        ".c",
        ".cc",
        ".cpp",
        ".h",
        ".hh",
        ".hpp",
        ".py",
        ".js",
        ".ts",
        ".java",
        ".go",
        ".rs",
        ".php",
        ".rb",
        ".swift",
        ".kt",
        ".json",
        ".xml",
        ".yaml",
        ".yml",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
        ".txt"
    };

    return allowed_extensions.find(extension) !=
           allowed_extensions.end();
}

std::vector<std::string> scan_directory(const std::string& path) {

    std::vector<std::string> files;

    const std::unordered_set<std::string> ignored_directories = {
        ".git",
        ".vscode",
        "build",
        "node_modules"
    };

    std::filesystem::recursive_directory_iterator iterator(path);
    std::filesystem::recursive_directory_iterator end;

    while (iterator != end) {

        const auto& entry = *iterator;

        if (entry.is_directory()) {

            const std::string directory_name =
                entry.path().filename().string();

            if (ignored_directories.find(directory_name) !=
                ignored_directories.end()) {

                iterator.disable_recursion_pending();
            }
        }
        else if (entry.is_regular_file()) {

            if (should_scan_file(entry.path().string())) {
                files.push_back(entry.path().string());
            }
        }

        ++iterator;
    }

    return files;
}

}