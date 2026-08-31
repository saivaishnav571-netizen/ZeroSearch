#include "rule_engine.h"

#include <fstream>
#include <sstream>
#include <vector>

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
        80,
        false
    });

    rules.push_back({
        "Generic API Token",
        "Detects API token assignments",
        std::regex(
            R"((api[_-]?token)\s*=\s*["']([^"']+)["'])",
            std::regex_constants::icase
        ),
        80,
        false
    });

    rules.push_back({
        "Secret Key",
        "Detects secret key assignments",
        std::regex(
            R"((secret[_-]?key)\s*=\s*["']([^"']+)["'])",
            std::regex_constants::icase
        ),
        80,
        false
    });

    rules.push_back({
        "Password",
        "Detects password assignments",
        std::regex(
            R"((password)\s*=\s*["']([^"']+)["'])",
            std::regex_constants::icase
        ),
        75,
        false
    });

    rules.push_back({
        "Credential",
        "Detects credential assignments",
        std::regex(
            R"((credential)\s*=\s*["']([^"']+)["'])",
            std::regex_constants::icase
        ),
        75,
        false
    });

    rules.push_back({
        "AWS Access Key",
        "Detects AWS access key identifiers",
        std::regex(
            R"(AKIA[0-9A-Z]{16})"
        ),
        90,
        false
    });

    rules.push_back({
        "GitHub Token",
        "Detects GitHub personal access tokens",
        std::regex(
            R"(gh[pousr]_[A-Za-z0-9_]{20,})"
        ),
        90,
        false
    });

    rules.push_back({
        "JWT",
        "Detects JSON Web Tokens",
        std::regex(
            R"(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"
        ),
        85,
        false
    });

    rules.push_back({
        "Private Key",
        "Detects private key blocks",
        std::regex(
            R"(-----BEGIN ([A-Z ]+)?PRIVATE KEY-----)"
        ),
        95,
        false
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

        line =
            line.substr(first_non_space);

        if (line.rfind("#", 0) == 0) {
            continue;
        }

        /*
            Custom rules are loaded separately.
        */

        if (line.rfind("custom|", 0) == 0) {
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


std::vector<DetectionRule> load_custom_rules(
    const std::string& path
) {

    std::vector<DetectionRule> custom_rules;

    std::ifstream input(path);

    if (!input.is_open()) {
        return custom_rules;
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

        line =
            line.substr(first_non_space);

        if (line.rfind("#", 0) == 0) {
            continue;
        }

        /*
            Custom rule format:

            custom|name|description|regex|confidence
        */

        if (line.rfind("custom|", 0) != 0) {
            continue;
        }

        std::vector<std::string> fields;

        std::stringstream stream(line);

        std::string field;

        while (std::getline(
            stream,
            field,
            '|'
        )) {

            fields.push_back(field);
        }

        if (fields.size() != 5) {
            continue;
        }

        const std::string name =
            fields[1];

        const std::string description =
            fields[2];

        const std::string pattern =
            fields[3];

        int confidence = 0;

        try {

            confidence =
                std::stoi(fields[4]);

        }
        catch (...) {

            continue;
        }

        if (name.empty() ||
            pattern.empty() ||
            confidence < 0 ||
            confidence > 100) {

            continue;
        }

        try {

            custom_rules.push_back({
                name,
                description,
                std::regex(pattern),
                confidence,
                true
            });

        }
        catch (const std::regex_error&) {

            /*
                Invalid custom regex.
                Ignore this rule rather than
                crashing the scanner.
            */

            continue;
        }
    }

    return custom_rules;
}


std::vector<Finding> apply_rules(
    const std::string& file,
    const std::string& content,
    const std::unordered_set<std::string>& enabled_rules,
    const std::vector<DetectionRule>& custom_rules
) {

    std::vector<Finding> findings;

    std::vector<DetectionRule> rules =
        create_default_rules();

    /*
        Add custom rules to the built-in rules.
    */

    rules.insert(
        rules.end(),
        custom_rules.begin(),
        custom_rules.end()
    );

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

        /*
            Ignore single-line comments.
        */

        if (trimmed.rfind("//", 0) == 0 ||
            trimmed.rfind("#", 0) == 0) {

            continue;
        }

        for (const DetectionRule& rule : rules) {

            /*
                Rule must be enabled.
            */

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

            finding.file =
                file;

            finding.line =
                line_number;

            finding.type =
                rule.name;

            finding.entropy =
                0.0;

            finding.confidence =
                rule.base_confidence;

            finding.severity =
                Severity::HIGH;

            /*
                Built-in assignment rules:

                group 1 = variable name
                group 2 = secret value

                Custom rules use the complete
                regex match.
            */

            if (!rule.custom &&
                match.size() >= 3) {

                finding.matched_text =
                    match[2].str();
            }

            else {

                finding.matched_text =
                    match[0].str();
            }

            findings.push_back(
                finding
            );
        }
    }

    return findings;
}

}