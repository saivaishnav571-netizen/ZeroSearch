#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "detector.h"
#include "finding.h"
#include "redactor.h"
#include "scanner.h"

std::string severity_to_string(zerotrace::Severity severity) {

    switch (severity) {

        case zerotrace::Severity::LOW:
            return "LOW";

        case zerotrace::Severity::MEDIUM:
            return "MEDIUM";

        case zerotrace::Severity::HIGH:
            return "HIGH";

        case zerotrace::Severity::CRITICAL:
            return "CRITICAL";
    }

    return "UNKNOWN";
}

std::string escape_json(const std::string& text) {

    std::string result;

    for (char character : text) {

        switch (character) {

            case '"':
                result += "\\\"";
                break;

            case '\\':
                result += "\\\\";
                break;

            case '\n':
                result += "\\n";
                break;

            case '\r':
                result += "\\r";
                break;

            case '\t':
                result += "\\t";
                break;

            default:
                result += character;
        }
    }

    return result;
}

int main(int argc, char* argv[]) {

    if (argc < 2) {
        std::cout << "Usage: zerotrace scan <directory> [--json]\n";
        return 1;
    }

    std::string command = argv[1];

    if (command != "scan") {

        std::cout << "Unknown command: "
                  << command
                  << "\n";

        std::cout << "Usage: zerotrace scan <directory> [--json]\n";

        return 1;
    }

    if (argc < 3) {

        std::cout << "Error: directory path is required.\n";
        std::cout << "Usage: zerotrace scan <directory> [--json]\n";

        return 1;
    }

    std::string path = argv[2];

    bool json_output = false;

    if (argc >= 4 && std::string(argv[3]) == "--json") {
        json_output = true;
    }

    std::vector<std::string> files =
        zerotrace::scan_directory(path);

    struct ScanResult {
        std::vector<zerotrace::Finding> findings;
    };

    ScanResult result;

    for (const std::string& file : files) {

        std::ifstream input(file);

        if (!input.is_open()) {
            continue;
        }

        std::string content(
            (std::istreambuf_iterator<char>(input)),
            std::istreambuf_iterator<char>()
        );

        std::vector<zerotrace::Finding> findings =
            zerotrace::detect_secrets(file, content);

        result.findings.insert(
            result.findings.end(),
            findings.begin(),
            findings.end()
        );
    }

    // JSON output mode.
    if (json_output) {

        std::cout << "{\n";

        std::cout << "  \"files_scanned\": "
                  << files.size()
                  << ",\n";

        std::cout << "  \"total_findings\": "
                  << result.findings.size()
                  << ",\n";

        std::cout << "  \"findings\": [\n";

        for (std::size_t i = 0;
             i < result.findings.size();
             ++i) {

            const auto& finding =
                result.findings[i];

            std::cout << "    {\n";

            std::cout << "      \"type\": \""
                      << escape_json(finding.type)
                      << "\",\n";

            std::cout << "      \"file\": \""
                      << escape_json(finding.file)
                      << "\",\n";

            std::cout << "      \"line\": "
                      << finding.line
                      << ",\n";

            std::cout << "      \"severity\": \""
                      << severity_to_string(
                             finding.severity)
                      << "\",\n";

            std::cout << "      \"confidence\": "
                      << finding.confidence
                      << ",\n";

            std::cout << "      \"entropy\": "
                      << std::fixed
                      << std::setprecision(2)
                      << finding.entropy
                      << ",\n";

            std::cout << "      \"value\": \""
                      << escape_json(
                             zerotrace::redact_secret(
                                 finding.matched_text))
                      << "\"\n";

            std::cout << "    }";

            if (i + 1 < result.findings.size()) {
                std::cout << ",";
            }

            std::cout << "\n";
        }

        std::cout << "  ]\n";
        std::cout << "}\n";

        return 0;
    }

    // Human-readable output.
    std::cout << "=================================\n";
    std::cout << "          ZeroTrace\n";
    std::cout << "   Secret Detection Engine\n";
    std::cout << "=================================\n\n";

    std::cout << "Scanning: "
              << path
              << "\n\n";

    std::cout << "Files scanned: "
              << files.size()
              << "\n\n";

    for (const auto& finding : result.findings) {

        std::cout << "["
                  << severity_to_string(
                         finding.severity)
                  << "] "
                  << finding.type
                  << "\n";

        std::cout << "  File: "
                  << finding.file
                  << "\n";

        std::cout << "  Line: "
                  << finding.line
                  << "\n";

        std::cout << "  Confidence: "
                  << finding.confidence
                  << "%\n";

        std::cout << "  Entropy: "
                  << std::fixed
                  << std::setprecision(2)
                  << finding.entropy
                  << "\n";

        std::cout << "  Value: "
                  << zerotrace::redact_secret(
                         finding.matched_text)
                  << "\n\n";
    }

    std::cout << "Total findings: "
              << result.findings.size()
              << "\n";

    return 0;
}