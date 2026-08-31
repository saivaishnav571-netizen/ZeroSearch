#include "rule_engine.h"

#include <sstream>

namespace zerotrace {

std::vector<DetectionRule> create_default_rules() {

    std::vector<DetectionRule> rules;

    rules.push_back({
        "Generic API Key",
        "Detects API key assignments",
        std::regex(
            R"((api[_-]?key)\s*=\s*["']([^"']+)["'])",
            std::regex_constants::icase
        ),
        80
    });

    rules.push_back({
        "Generic API Token",
        "Detects API token assignments",
        std::regex(
            R"((api[_-]?token)\s*=\s*["']([^"']+)["'])",
            std::regex_constants::icase
        ),
        80
    });

    rules.push_back({
        "Secret Key",
        "Detects secret key assignments",
        std::regex(
            R"((secret[_-]?key)\s*=\s*["']([^"']+)["'])",
            std::regex_constants::icase
        ),
        80
    });

    rules.push_back({
        "Password",
        "Detects password assignments",
        std::regex(
            R"((password)\s*=\s*["']([^"']+)["'])",
            std::regex_constants::icase
        ),
        75
    });

    rules.push_back({
        "Credential",
        "Detects credential assignments",
        std::regex(
            R"((credential)\s*=\s*["']([^"']+)["'])",
            std::regex_constants::icase
        ),
        75
    });

    rules.push_back({
        "AWS Access Key",
        "Detects AWS access key identifiers",
        std::regex(
            R"(AKIA[0-9A-Z]{16})"
        ),
        90
    });

    rules.push_back({
        "GitHub Token",
        "Detects GitHub personal access tokens",
        std::regex(
            R"(gh[pousr]_[A-Za-z0-9_]{20,})"
        ),
        90
    });

    rules.push_back({
        "JWT",
        "Detects JSON Web Tokens",
        std::regex(
            R"(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"
        ),
        85
    });

    rules.push_back({
        "Private Key",
        "Detects private key blocks",
        std::regex(
            R"(-----BEGIN ([A-Z ]+)?PRIVATE KEY-----)"
        ),
        95
    });

    return rules;
}

std::vector<Finding> apply_rules(
    const std::string& file,
    const std::string& content
) {

    std::vector<Finding> findings;

    const std::vector<DetectionRule> rules =
        create_default_rules();

    std::istringstream stream(content);

    std::string line;
    int line_number = 0;

    while (std::getline(stream, line)) {

        ++line_number;

        std::string trimmed = line;

        const std::size_t first_non_space =
            trimmed.find_first_not_of(" \t");

        if (first_non_space != std::string::npos) {
            trimmed = trimmed.substr(first_non_space);
        }

        if (trimmed.rfind("//", 0) == 0 ||
            trimmed.rfind("#", 0) == 0) {
            continue;
        }

        for (const DetectionRule& rule : rules) {

            std::smatch match;

            if (std::regex_search(
                    line,
                    match,
                    rule.pattern)) {

                Finding finding;

                finding.file = file;
                finding.line = line_number;
                finding.type = rule.name;

                if (match.size() > 1) {
                    finding.matched_text =
                        match[match.size() - 1].str();
                }

                finding.confidence =
                    rule.base_confidence;

                finding.severity = Severity::HIGH;

                findings.push_back(finding);
            }
        }
    }

    return findings;
}

}