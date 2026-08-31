#include "detector.h"

#include <regex>
#include <sstream>

namespace zerotrace {

std::vector<Finding> detect_secrets(
    const std::string& file,
    const std::string& content
) {
    std::vector<Finding> findings;

    /*
        Detect credential-like assignments such as:

        api_key = "..."
        api_token = "..."
        secret_key = "..."
        password = "..."
        credential = "..."
    */

    const std::regex secret_pattern(
        R"((api[_-]?key|api[_-]?token|secret[_-]?key|password|credential)\s*=\s*["']([^"']+)["'])",
        std::regex_constants::icase
    );

    std::istringstream stream(content);
    std::string line;
    int line_number = 0;

    while (std::getline(stream, line)) {

        ++line_number;

        // Remove leading whitespace.
        std::string trimmed = line;

        const std::size_t first_non_space =
            trimmed.find_first_not_of(" \t");

        if (first_non_space != std::string::npos) {
            trimmed = trimmed.substr(first_non_space);
        }

        // Ignore single-line comments.
        if (trimmed.rfind("//", 0) == 0 ||
            trimmed.rfind("#", 0) == 0) {
            continue;
        }

        std::smatch match;

        if (std::regex_search(line, match, secret_pattern)) {

            Finding finding;

            finding.file = file;
            finding.line = line_number;
            finding.type = "Potential Secret";
            finding.matched_text = match[2].str();
            finding.severity = Severity::HIGH;
            finding.confidence = 80;

            findings.push_back(finding);
        }
    }

    return findings;
}

}