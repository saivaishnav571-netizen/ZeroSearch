#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "detector.h"
#include "finding.h"
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

int main(int argc, char* argv[]) {

    std::cout << "=================================\n";
    std::cout << "          ZeroTrace\n";
    std::cout << "   Secret Detection Engine\n";
    std::cout << "=================================\n\n";

    if (argc < 2) {
        std::cout << "Usage: zerotrace scan <directory>\n";
        return 1;
    }

    std::string command = argv[1];

    if (command == "scan") {

        if (argc < 3) {
            std::cout << "Error: directory path is required.\n";
            std::cout << "Usage: zerotrace scan <directory>\n";
            return 1;
        }

        std::string path = argv[2];

        std::cout << "Scanning: " << path << "\n\n";

        std::vector<std::string> files =
            zerotrace::scan_directory(path);

        std::cout << "Files scanned: "
                  << files.size()
                  << "\n\n";

        int total_findings = 0;

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

            for (const auto& finding : findings) {

                std::cout << "["
                          << severity_to_string(finding.severity)
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
                          << "%\n\n";

                ++total_findings;
            }
        }

        std::cout << "Total findings: "
                  << total_findings
                  << "\n";

        return 0;
    }

    std::cout << "Unknown command: " << command << "\n";
    std::cout << "Usage: zerotrace scan <directory>\n";

    return 1;
}