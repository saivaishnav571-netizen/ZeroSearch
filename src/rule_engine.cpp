#include "rule_engine.h"

#include <fstream>
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

std::unordered_set<std::string> load_enabled_rules(
    const std::string& path
) {

    std::unordered_set<std::string> enabled_rules;

    std::ifstream input(path);

    if (!input.is_open()) {
        return enabled_rules;
    }

    std::string line;

    while (std::getline(input, line)) {

        if (line.empty()) {
            continue;
        }

        const std::size_t first_non_space =
            line.find_first_not_of(" \t");

        if (first_non_space == std::string::npos) {
            continue;
        }

        line = line.substr(first_non_space);

        if (line.rfind("#", 0) == 0) {
            continue;
        }

        const std::size_t separator =
            line.find('=');

        if (separator == std::string::npos) {
            continue;
        }

        std::string rule_name =
            line.substr(0, separator);

        std::string state =
            line.substr(separator + 1);

        while (!rule_name.empty() &&
               (rule_name.back() == ' ' ||
                rule_name.back() == '\t')) {

            rule_name.pop_back();
        }

        while (!state.empty() &&
               (state.front() == ' ' ||
                state.front() == '\t')) {

            state.erase(state.begin());
        }

        if (state == "enabled") {
            enabled_rules.insert(rule_name);
        }
    }

    return enabled_rules;
}

std::vector<Finding> apply_rules(
    const std::string& file,
    const std::string& content,
    const std::unordered_set<std::string>& enabled_rules
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
            trimmed =
                trimmed.substr(first_non_space);
        }

        // Ignore single-line comments.
        if (trimmed.rfind("//", 0) == 0 ||
            trimmed.rfind("#", 0) == 0) {

            continue;
        }

        for (const DetectionRule& rule : rules) {

            if (enabled_rules.find(rule.name) ==
                enabled_rules.end()) {

                continue;
            }

            std::smatch match;

            if (!std::regex_search(
                    line,
                    match,
                    rule.pattern)) {

                continue;
            }

            Finding finding;

            finding.file = file;
            finding.line = line_number;
            finding.type = rule.name;
            finding.entropy = 0.0;
            finding.confidence =
                rule.base_confidence;
            finding.severity = Severity::HIGH;

            if (match.size() >= 3) {
                finding.matched_text =
                    match[2].str();
            }
            else {
                finding.matched_text =
                    match[0].str();
            }

            findings.push_back(finding);
        }
    }

    return findings;
}

}