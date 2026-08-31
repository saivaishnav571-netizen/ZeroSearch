#include <fstream>
#include <future>
#include <iomanip>
#include <iostream>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include "baseline.h"
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

std::string normalize_path(std::string path) {

    for (char& character : path) {

        if (character == '\\') {
            character = '/';
        }
    }

    return path;
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

        std::cout
            << "Usage: zerotrace scan <directory> "
               "[--json] "
               "[--save-baseline <file>] "
               "[--baseline <file>]\n";

        return 2;
    }

    const std::string command = argv[1];

    if (command != "scan") {

        std::cout
            << "Unknown command: "
            << command
            << "\n";

        return 2;
    }

    if (argc < 3) {

        std::cout
            << "Error: directory path is required.\n";

        return 2;
    }

    const std::string path = argv[2];

    bool json_output = false;

    std::string save_baseline_path;
    std::string baseline_path;

    for (int i = 3; i < argc; ++i) {

        std::string argument = argv[i];

        if (argument == "--json") {

            json_output = true;
        }

        else if (argument == "--save-baseline") {

            if (i + 1 >= argc) {

                std::cerr
                    << "Error: --save-baseline "
                       "requires a file path.\n";

                return 2;
            }

            save_baseline_path = argv[++i];
        }

        else if (argument == "--baseline") {

            if (i + 1 >= argc) {

                std::cerr
                    << "Error: --baseline "
                       "requires a file path.\n";

                return 2;
            }

            baseline_path = argv[++i];
        }

        else {

            std::cerr
                << "Unknown option: "
                << argument
                << "\n";

            return 2;
        }
    }

    /*
        Find files to scan.
    */

    std::vector<std::string> files =
        zerotrace::scan_directory(path);

    /*
        Multithreaded scanning.

        Each file is scanned independently in its
        own asynchronous task.

        We do NOT modify all_findings from worker
        threads. Each worker returns its own vector,
        and the main thread combines the results.
    */

    std::vector<
        std::future<std::vector<zerotrace::Finding>>
    > tasks;

    tasks.reserve(files.size());

    for (const std::string& file : files) {

        tasks.push_back(
            std::async(
                std::launch::async,
                [file]() {

                    std::vector<zerotrace::Finding> findings;

                    std::ifstream input(file);

                    if (!input.is_open()) {
                        return findings;
                    }

                    std::string content(
                        (std::istreambuf_iterator<char>(input)),
                        std::istreambuf_iterator<char>()
                    );

                    return zerotrace::detect_secrets(
                        file,
                        content
                    );
                }
            )
        );
    }

    /*
        Collect results from worker threads.
    */

    std::vector<zerotrace::Finding> all_findings;

    for (auto& task : tasks) {

        std::vector<zerotrace::Finding> findings =
            task.get();

        all_findings.insert(
            all_findings.end(),
            findings.begin(),
            findings.end()
        );
    }

    /*
        Save baseline.
    */

    if (!save_baseline_path.empty()) {

        if (!zerotrace::save_baseline(
                save_baseline_path,
                all_findings)) {

            std::cerr
                << "Error: could not save baseline to "
                << save_baseline_path
                << "\n";

            return 2;
        }

        if (!json_output) {

            std::cout
                << "Baseline saved to: "
                << save_baseline_path
                << "\n";

            std::cout
                << "Findings saved: "
                << all_findings.size()
                << "\n";
        }
    }

    /*
        Load baseline.
    */

    std::unordered_set<std::string> baseline;

    if (!baseline_path.empty()) {

        baseline =
            zerotrace::load_baseline(baseline_path);

        if (baseline.empty()) {

            std::ifstream test_file(
                baseline_path
            );

            if (!test_file.is_open()) {

                std::cerr
                    << "Error: could not open baseline: "
                    << baseline_path
                    << "\n";

                return 2;
            }
        }
    }

    /*
        Calculate new findings.
    */

    int new_findings = 0;

    for (const auto& finding : all_findings) {

        if (!baseline_path.empty()) {

            const std::string fingerprint =
                zerotrace::create_finding_fingerprint(
                    finding
                );

            if (baseline.find(fingerprint) ==
                baseline.end()) {

                ++new_findings;
            }
        }
    }

    /*
        JSON output.
    */

    if (json_output) {

        std::cout << "{\n";

        std::cout
            << "  \"files_scanned\": "
            << files.size()
            << ",\n";

        std::cout
            << "  \"total_findings\": "
            << all_findings.size()
            << ",\n";

        if (!baseline_path.empty()) {

            std::cout
                << "  \"new_findings\": "
                << new_findings
                << ",\n";
        }

        std::cout
            << "  \"findings\": [\n";

        for (std::size_t i = 0;
             i < all_findings.size();
             ++i) {

            const auto& finding =
                all_findings[i];

            bool is_new = false;

            if (!baseline_path.empty()) {

                const std::string fingerprint =
                    zerotrace::create_finding_fingerprint(
                        finding
                    );

                is_new =
                    baseline.find(fingerprint) ==
                    baseline.end();
            }

            std::cout << "    {\n";

            std::cout
                << "      \"type\": \""
                << escape_json(finding.type)
                << "\",\n";

            std::cout
                << "      \"file\": \""
                << escape_json(
                       normalize_path(finding.file))
                << "\",\n";

            std::cout
                << "      \"line\": "
                << finding.line
                << ",\n";

            std::cout
                << "      \"severity\": \""
                << severity_to_string(
                       finding.severity)
                << "\",\n";

            std::cout
                << "      \"confidence\": "
                << finding.confidence
                << ",\n";

            std::cout
                << "      \"entropy\": "
                << std::fixed
                << std::setprecision(2)
                << finding.entropy
                << ",\n";

            std::cout
                << "      \"value\": \""
                << escape_json(
                       zerotrace::redact_secret(
                           finding.matched_text))
                << "\"";

            if (!baseline_path.empty()) {

                std::cout
                    << ",\n"
                    << "      \"new\": "
                    << (is_new ? "true" : "false");
            }

            std::cout << "\n";
            std::cout << "    }";

            if (i + 1 < all_findings.size()) {
                std::cout << ",";
            }

            std::cout << "\n";
        }

        std::cout
            << "  ]\n"
            << "}\n";

        /*
            Exit code:

            0 = no findings / no new findings
            1 = findings or new findings
            2 = scanner error
        */

        if (!baseline_path.empty()) {
            return new_findings > 0 ? 1 : 0;
        }

        return all_findings.empty() ? 0 : 1;
    }

    /*
        Human-readable output.
    */

    std::cout
        << "=================================\n"
        << "          ZeroTrace\n"
        << "   Secret Detection Engine\n"
        << "=================================\n\n";

    std::cout
        << "Scanning: "
        << path
        << "\n\n";

    std::cout
        << "Files scanned: "
        << files.size()
        << "\n\n";

    for (const auto& finding : all_findings) {

        bool is_new = false;

        if (!baseline_path.empty()) {

            const std::string fingerprint =
                zerotrace::create_finding_fingerprint(
                    finding
                );

            is_new =
                baseline.find(fingerprint) ==
                baseline.end();
        }

        if (!baseline_path.empty()) {

            std::cout
                << (is_new ? "[NEW] " : "[KNOWN] ");
        }

        std::cout
            << "["
            << severity_to_string(
                   finding.severity)
            << "] "
            << finding.type
            << "\n";

        std::cout
            << "  File: "
            << normalize_path(finding.file)
            << "\n";

        std::cout
            << "  Line: "
            << finding.line
            << "\n";

        std::cout
            << "  Confidence: "
            << finding.confidence
            << "%\n";

        std::cout
            << "  Entropy: "
            << std::fixed
            << std::setprecision(2)
            << finding.entropy
            << "\n";

        std::cout
            << "  Value: "
            << zerotrace::redact_secret(
                   finding.matched_text)
            << "\n\n";
    }

    std::cout
        << "Total findings: "
        << all_findings.size()
        << "\n";

    if (!baseline_path.empty()) {

        std::cout
            << "New findings: "
            << new_findings
            << "\n";
    }

    if (!baseline_path.empty()) {
        return new_findings > 0 ? 1 : 0;
    }

    return all_findings.empty() ? 0 : 1;
}