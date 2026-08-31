#include <fstream>
#include <future>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include "baseline.h"
#include "detector.h"
#include "finding.h"
#include "redactor.h"
#include "rule_engine.h"
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

std::string build_json_report(
    const std::vector<zerotrace::Finding>& all_findings,
    std::size_t files_scanned,
    unsigned int thread_count,
    const std::string& rules_path,
    const std::unordered_set<std::string>& baseline,
    const std::string& baseline_path,
    int new_findings
) {

    std::ostringstream output;

    output << "{\n";

    output
        << "  \"files_scanned\": "
        << files_scanned
        << ",\n";

    output
        << "  \"threads\": "
        << thread_count
        << ",\n";

    output
        << "  \"rules_file\": \""
        << escape_json(rules_path)
        << "\",\n";

    output
        << "  \"total_findings\": "
        << all_findings.size()
        << ",\n";

    if (!baseline_path.empty()) {

        output
            << "  \"new_findings\": "
            << new_findings
            << ",\n";
    }

    output
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

        output << "    {\n";

        output
            << "      \"type\": \""
            << escape_json(finding.type)
            << "\",\n";

        output
            << "      \"file\": \""
            << escape_json(
                   normalize_path(finding.file))
            << "\",\n";

        output
            << "      \"line\": "
            << finding.line
            << ",\n";

        output
            << "      \"severity\": \""
            << severity_to_string(
                   finding.severity)
            << "\",\n";

        output
            << "      \"confidence\": "
            << finding.confidence
            << ",\n";

        output
            << "      \"entropy\": "
            << std::fixed
            << std::setprecision(2)
            << finding.entropy
            << ",\n";

        output
            << "      \"value\": \""
            << escape_json(
                   zerotrace::redact_secret(
                       finding.matched_text))
            << "\"";

        if (!baseline_path.empty()) {

            output
                << ",\n"
                << "      \"new\": "
                << (is_new ? "true" : "false");
        }

        output << "\n";
        output << "    }";

        if (i + 1 < all_findings.size()) {
            output << ",";
        }

        output << "\n";
    }

    output
        << "  ]\n"
        << "}\n";

    return output.str();
}

std::string build_text_report(
    const std::vector<zerotrace::Finding>& all_findings,
    const std::string& path,
    std::size_t files_scanned,
    unsigned int thread_count,
    const std::unordered_set<std::string>& baseline,
    const std::string& baseline_path,
    int new_findings
) {

    std::ostringstream output;

    output
        << "=================================\n"
        << "          ZeroTrace\n"
        << "   Secret Detection Engine\n"
        << "=================================\n\n";

    output
        << "Scanning: "
        << path
        << "\n\n";

    output
        << "Files scanned: "
        << files_scanned
        << "\n";

    output
        << "Threads: "
        << thread_count
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

            output
                << (is_new ? "[NEW] " : "[KNOWN] ");
        }

        output
            << "["
            << severity_to_string(
                   finding.severity)
            << "] "
            << finding.type
            << "\n";

        output
            << "  File: "
            << normalize_path(finding.file)
            << "\n";

        output
            << "  Line: "
            << finding.line
            << "\n";

        output
            << "  Confidence: "
            << finding.confidence
            << "%\n";

        output
            << "  Entropy: "
            << std::fixed
            << std::setprecision(2)
            << finding.entropy
            << "\n";

        output
            << "  Value: "
            << zerotrace::redact_secret(
                   finding.matched_text)
            << "\n\n";
    }

    output
        << "Total findings: "
        << all_findings.size()
        << "\n";

    if (!baseline_path.empty()) {

        output
            << "New findings: "
            << new_findings
            << "\n";
    }

    return output.str();
}

int main(int argc, char* argv[]) {

    if (argc < 2) {

        std::cout
            << "Usage: zerotrace scan <directory> "
               "[--json] "
               "[--output <file>] "
               "[--save-baseline <file>] "
               "[--baseline <file>] "
               "[--threads <number>] "
               "[--rules <file>]\n";

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

    std::string output_path;
    std::string save_baseline_path;
    std::string baseline_path;

    std::string rules_path = "rules.conf";

    unsigned int thread_count =
        std::thread::hardware_concurrency();

    if (thread_count == 0) {
        thread_count = 1;
    }

    /*
        Parse command-line options.
    */

    for (int i = 3; i < argc; ++i) {

        std::string argument = argv[i];

        if (argument == "--json") {

            json_output = true;
        }

        else if (argument == "--output") {

            if (i + 1 >= argc) {

                std::cerr
                    << "Error: --output "
                       "requires a file path.\n";

                return 2;
            }

            output_path = argv[++i];
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

        else if (argument == "--threads") {

            if (i + 1 >= argc) {

                std::cerr
                    << "Error: --threads "
                       "requires a number.\n";

                return 2;
            }

            try {

                const unsigned long parsed =
                    std::stoul(argv[++i]);

                if (parsed == 0) {

                    std::cerr
                        << "Error: thread count "
                           "must be greater than 0.\n";

                    return 2;
                }

                thread_count =
                    static_cast<unsigned int>(parsed);
            }
            catch (...) {

                std::cerr
                    << "Error: invalid thread count.\n";

                return 2;
            }
        }

        else if (argument == "--rules") {

            if (i + 1 >= argc) {

                std::cerr
                    << "Error: --rules "
                       "requires a file path.\n";

                return 2;
            }

            rules_path = argv[++i];
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
        Load enabled detection rules once.
    */

    std::unordered_set<std::string> enabled_rules =
        zerotrace::load_enabled_rules(rules_path);

    /*
        If rules.conf doesn't exist,
        enable all default rules.
    */

    if (enabled_rules.empty()) {

        std::ifstream rules_file(rules_path);

        if (!rules_file.is_open()) {

            const std::vector<zerotrace::DetectionRule>
                default_rules =
                    zerotrace::create_default_rules();

            for (const auto& rule : default_rules) {
                enabled_rules.insert(rule.name);
            }
        }
    }

    /*
        Find files.
    */

    std::vector<std::string> files =
        zerotrace::scan_directory(path);

    /*
        Don't create more workers than files.
    */

    if (!files.empty() &&
        thread_count > files.size()) {

        thread_count =
            static_cast<unsigned int>(files.size());
    }

    if (files.empty()) {
        thread_count = 1;
    }

    /*
        Multithreaded scanning.
    */

    std::vector<
        std::future<std::vector<zerotrace::Finding>>
    > tasks;

    tasks.reserve(thread_count);

    const std::size_t total_files =
        files.size();

    const std::size_t base_files_per_thread =
        total_files / thread_count;

    const std::size_t extra_files =
        total_files % thread_count;

    std::size_t start_index = 0;

    for (unsigned int worker = 0;
         worker < thread_count;
         ++worker) {

        const std::size_t files_for_worker =
            base_files_per_thread +
            (worker < extra_files ? 1 : 0);

        const std::size_t worker_start =
            start_index;

        const std::size_t worker_end =
            worker_start + files_for_worker;

        start_index = worker_end;

        tasks.push_back(
            std::async(
                std::launch::async,
                [&files,
                 &enabled_rules,
                 worker_start,
                 worker_end]() {

                    std::vector<zerotrace::Finding>
                        worker_findings;

                    for (std::size_t i = worker_start;
                         i < worker_end;
                         ++i) {

                        const std::string& file =
                            files[i];

                        std::ifstream input(file);

                        if (!input.is_open()) {
                            continue;
                        }

                        std::string content(
                            (std::istreambuf_iterator<char>(
                                input)),
                            std::istreambuf_iterator<char>()
                        );

                        std::vector<zerotrace::Finding>
                            findings =
                                zerotrace::detect_secrets(
                                    file,
                                    content,
                                    enabled_rules
                                );

                        worker_findings.insert(
                            worker_findings.end(),
                            findings.begin(),
                            findings.end()
                        );
                    }

                    return worker_findings;
                }
            )
        );
    }

    /*
        Collect worker results.
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

        if (!json_output && output_path.empty()) {

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
        Build the report.
    */

    std::string report;

    if (json_output) {

        report = build_json_report(
            all_findings,
            files.size(),
            thread_count,
            rules_path,
            baseline,
            baseline_path,
            new_findings
        );
    }

    else {

        report = build_text_report(
            all_findings,
            path,
            files.size(),
            thread_count,
            baseline,
            baseline_path,
            new_findings
        );
    }

    /*
        Write report to file if requested.
    */

    if (!output_path.empty()) {

        std::ofstream output_file(
            output_path
        );

        if (!output_file.is_open()) {

            std::cerr
                << "Error: could not write output file: "
                << output_path
                << "\n";

            return 2;
        }

        output_file << report;

        output_file.close();

        std::cout
            << "Report written to: "
            << output_path
            << "\n";
    }

    else {

        /*
            Preserve normal terminal behavior.
        */

        std::cout << report;
    }

    /*
        Exit codes:

        0 = no findings / no new findings
        1 = findings or new findings
        2 = scanner error
    */

    if (!baseline_path.empty()) {
        return new_findings > 0 ? 1 : 0;
    }

    return all_findings.empty() ? 0 : 1;
}