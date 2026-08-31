#include "baseline.h"

#include <fstream>
#include <string>

namespace zerotrace {

static std::string normalize_path(std::string path) {

    for (char& character : path) {

        if (character == '\\') {
            character = '/';
        }
    }

    return path;
}

std::string create_finding_fingerprint(
    const Finding& finding
) {

    return normalize_path(finding.file) +
           "|" +
           std::to_string(finding.line) +
           "|" +
           finding.type;
}

bool save_baseline(
    const std::string& path,
    const std::vector<Finding>& findings
) {

    std::ofstream output(path);

    if (!output.is_open()) {
        return false;
    }

    for (const Finding& finding : findings) {

        output << create_finding_fingerprint(finding)
               << "\n";
    }

    return true;
}

std::unordered_set<std::string> load_baseline(
    const std::string& path
) {

    std::unordered_set<std::string> baseline;

    std::ifstream input(path);

    if (!input.is_open()) {
        return baseline;
    }

    std::string line;

    while (std::getline(input, line)) {

        if (!line.empty()) {
            baseline.insert(normalize_path(line));
        }
    }

    return baseline;
}

}