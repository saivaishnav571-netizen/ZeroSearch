#include <chrono>
#include <fstream>
#include <future>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include "allowlist.h"
#include "baseline.h"
#include "detector.h"
#include "finding.h"
#include "redactor.h"
#include "rule_engine.h"
#include "scanner.h"
#include "sarif.h"


std::string severity_to_string(
    zerotrace::Severity severity
) {

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


std::string normalize_path(
    std::string path
) {

    for (char& character : path) {

        if (character == '\\') {
            character = '/';
        }
    }

    return path;
}


std::string escape_json(
    const std::string& text
) {

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


/*
    Count findings by severity.
*/

std::map<std::string, int>
count_by_severity(
    const std::vector<zerotrace::Finding>& findings
) {

    std::map<std::string, int> counts;

    for (const auto& finding : findings) {

        counts[
            severity_to_string(
                finding.severity
            )
        ]++;
    }

    return counts;
}


/*
    Count findings by detection rule.
*/

std::map<std::string, int>
count_by_rule(
    const std::vector<zerotrace::Finding>& findings
) {

    std::map<std::string, int> counts;

    for (const auto& finding : findings) {

        counts[finding.type]++;
    }

    return counts;
}


std::string build_json_report(
    const std::vector<zerotrace::Finding>& all_findings,
    std::size_t files_scanned,
    unsigned int thread_count,
    const std::string& rules_path,
    const std::unordered_set<std::string>& baseline,
    const std::string& baseline_path,
    int new_findings,
    double scan_time_seconds
) {

    std::ostringstream output;

    const auto severity_counts =
        count_by_severity(
            all_findings
        );

    const auto rule_counts =
        count_by_rule(
            all_findings
        );

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
        << "  \"scan_time_seconds\": "
        << std::fixed
        << std::setprecision(3)
        << scan_time_seconds
        << ",\n";

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

    /*
        Severity statistics.
    */

    output
        << "  \"severity_counts\": {\n";


    output
        << "    \"LOW\": "
        << (
            severity_counts.count("LOW")
                ? severity_counts.at("LOW")
                : 0
        )
        << ",\n";

    output
        << "    \"MEDIUM\": "
        << (
            severity_counts.count("MEDIUM")
                ? severity_counts.at("MEDIUM")
                : 0
        )
        << ",\n";

    output
        << "    \"HIGH\": "
        << (
            severity_counts.count("HIGH")
                ? severity_counts.at("HIGH")
                : 0
        )
        << ",\n";

    output
        << "    \"CRITICAL\": "
        << (
            severity_counts.count("CRITICAL")
                ? severity_counts.at("CRITICAL")
                : 0
        )
        << "\n";

    output
        << "  },\n";

    /*
        Rule statistics.
    */

    output
        << "  \"rule_counts\": {\n";

    std::size_t rule_index = 0;

    for (const auto& entry : rule_counts) {

        output
            << "    \""
            << escape_json(entry.first)
            << "\": "
            << entry.second;

        if (++rule_index < rule_counts.size()) {
            output << ",";
        }

        output << "\n";
    }

    output
        << "  },\n";

    /*
        Individual findings.
    */

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
                   normalize_path(
                       finding.file
                   )
               )
            << "\",\n";

        output
            << "      \"line\": "
            << finding.line
            << ",\n";

        output
            << "      \"severity\": \""
            << severity_to_string(
                   finding.severity
               )
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
                       finding.matched_text
                   )
               )
            << "\"";

        if (!baseline_path.empty()) {

            output
                << ",\n"
                << "      \"new\": "
                << (
                    is_new
                        ? "true"
                        : "false"
                );
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
    int new_findings,
    double scan_time_seconds
) {

    std::ostringstream output;

    const auto severity_counts =
        count_by_severity(
            all_findings
        );

    const auto rule_counts =
        count_by_rule(
            all_findings
        );

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

    for (const auto& finding :
         all_findings) {

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
                << (
                    is_new
                        ? "[NEW] "
                        : "[KNOWN] "
                );
        }

        output
            << "["
            << severity_to_string(
                   finding.severity
               )
            << "] "
            << finding.type
            << "\n";

        output
            << "  File: "
            << normalize_path(
                   finding.file
               )
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
                   finding.matched_text
               )
            << "\n\n";
    }

    /*
        Summary.
    */

    output
        << "---------------------------------\n"
        << "Scan Statistics\n"
        << "---------------------------------\n";

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

    output
        << "\nFindings by severity:\n";

    output
        << "  CRITICAL: "
        << (
            severity_counts.count("CRITICAL")
                ? severity_counts.at("CRITICAL")
                : 0
        )
        << "\n";

    output
        << "  HIGH:     "
        << (
            severity_counts.count("HIGH")
                ? severity_counts.at("HIGH")
                : 0
        )
        << "\n";

    output
        << "  MEDIUM:   "
        << (
            severity_counts.count("MEDIUM")
                ? severity_counts.at("MEDIUM")
                : 0
        )
        << "\n";

    output
        << "  LOW:      "
        << (
            severity_counts.count("LOW")
                ? severity_counts.at("LOW")
                : 0
        )
        << "\n";

    output
        << "\nFindings by rule:\n";

    for (const auto& entry :
         rule_counts) {

        output
            << "  "
            << entry.first
            << ": "
            << entry.second
            << "\n";
    }

    output
        << "\nScan time: "
        << std::fixed
        << std::setprecision(3)
        << scan_time_seconds
        << "s\n";

    return output.str();
}


int main(
    int argc,
    char* argv[]
) {

    /*
        Start timer as early as possible.
    */

    const auto scan_start =
        std::chrono::steady_clock::now();

    if (argc < 2) {

        std::cout
            << "Usage: zerotrace scan <directory> "
               "[--json] "
               "[--sarif] "
               "[--output <file>] "
               "[--save-baseline <file>] "
               "[--baseline <file>] "
               "[--threads <number>] "
               "[--rules <file>] "
               "[--allowlist <file>]\n";

        return 2;
    }

    const std::string command =
        argv[1];

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

    const std::string path =
        argv[2];

    bool json_output = false;
    bool sarif_output = false;

    std::string output_path;
    std::string save_baseline_path;
    std::string baseline_path;
    std::string rules_path = "rules.conf";
    std::string allowlist_path;

    unsigned int thread_count =
        std::thread::hardware_concurrency();

    if (thread_count == 0) {
        thread_count = 1;
    }

    /*
        Parse command-line options.
    */

    for (int i = 3;
         i < argc;
         ++i) {

        std::string argument =
            argv[i];

        if (argument == "--json") {

            json_output = true;
        }

        else if (argument == "--sarif") {

            sarif_output = true;
        }

        else if (argument == "--output") {

            if (i + 1 >= argc) {

                std::cerr
                    << "Error: --output "
                       "requires a file path.\n";

                return 2;
            }

            output_path =
                argv[++i];
        }

        else if (argument ==
                 "--save-baseline") {

            if (i + 1 >= argc) {

                std::cerr
                    << "Error: --save-baseline "
                       "requires a file path.\n";

                return 2;
            }

            save_baseline_path =
                argv[++i];
        }

        else if (argument ==
                 "--baseline") {

            if (i + 1 >= argc) {

                std::cerr
                    << "Error: --baseline "
                       "requires a file path.\n";

                return 2;
            }

            baseline_path =
                argv[++i];
        }

        else if (argument ==
                 "--threads") {

            if (i + 1 >= argc) {

                std::cerr
                    << "Error: --threads "
                       "requires a number.\n";

                return 2;
            }

            try {

                const unsigned long parsed =
                    std::stoul(
                        argv[++i]
                    );

                if (parsed == 0) {

                    std::cerr
                        << "Error: thread count "
                           "must be greater than 0.\n";

                    return 2;
                }

                thread_count =
                    static_cast<unsigned int>(
                        parsed
                    );
            }

            catch (...) {

                std::cerr
                    << "Error: invalid thread count.\n";

                return 2;
            }
        }

        else if (argument ==
                 "--rules") {

            if (i + 1 >= argc) {

                std::cerr
                    << "Error: --rules "
                       "requires a file path.\n";

                return 2;
            }

            rules_path =
                argv[++i];
        }

        else if (argument ==
                 "--allowlist") {

            if (i + 1 >= argc) {

                std::cerr
                    << "Error: --allowlist "
                       "requires a file path.\n";

                return 2;
            }

            allowlist_path =
                argv[++i];
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
        Prevent conflicting formats.
    */

    if (json_output &&
        sarif_output) {

        std::cerr
            << "Error: --json and --sarif "
               "cannot be used together.\n";

        return 2;
    }

    /*
        Load enabled rules.
    */

    std::unordered_set<std::string>
        enabled_rules =
            zerotrace::load_enabled_rules(
                rules_path
            );

    /*
        Load custom rules.
    */

    std::vector<zerotrace::DetectionRule>
        custom_rules =
            zerotrace::load_custom_rules(
                rules_path
            );

    /*
        If rules.conf does not exist,
        enable all default rules.
    */

    if (enabled_rules.empty() &&
        custom_rules.empty()) {

        std::ifstream rules_file(
            rules_path
        );

        if (!rules_file.is_open()) {

            const std::vector<
                zerotrace::DetectionRule
            > default_rules =
                zerotrace::create_default_rules();

            for (const auto& rule :
                 default_rules) {

                enabled_rules.insert(
                    rule.name
                );
            }
        }
    }

    /*
        Enable custom rules.
    */

    for (const auto& rule :
         custom_rules) {

        enabled_rules.insert(
            rule.name
        );
    }

    /*
        Load allowlist.
    */

    zerotrace::Allowlist allowlist;

    if (!allowlist_path.empty()) {

        std::ifstream allowlist_file(
            allowlist_path
        );

        if (!allowlist_file.is_open()) {

            std::cerr
                << "Error: could not open allowlist: "
                << allowlist_path
                << "\n";

            return 2;
        }

        allowlist =
            zerotrace::load_allowlist(
                allowlist_path
            );
    }

    /*
        Find files.
    */

    std::vector<std::string> files =
        zerotrace::scan_directory(
            path
        );

    /*
        Don't create more workers
        than files.
    */

    if (!files.empty() &&
        thread_count > files.size()) {

        thread_count =
            static_cast<unsigned int>(
                files.size()
            );
    }

    if (files.empty()) {
        thread_count = 1;
    }

    /*
        Multithreaded scanning.
    */

    std::vector<
        std::future<
            std::vector<zerotrace::Finding>
        >
    > tasks;

    tasks.reserve(
        thread_count
    );

    const std::size_t total_files =
        files.size();

    const std::size_t
        base_files_per_thread =
            total_files /
            thread_count;

    const std::size_t
        extra_files =
            total_files %
            thread_count;

    std::size_t start_index = 0;

    for (unsigned int worker = 0;
         worker < thread_count;
         ++worker) {

        const std::size_t
            files_for_worker =
                base_files_per_thread +
                (
                    worker <
                    extra_files
                        ? 1
                        : 0
                );

        const std::size_t
            worker_start =
                start_index;

        const std::size_t
            worker_end =
                worker_start +
                files_for_worker;

        start_index =
            worker_end;

        tasks.push_back(
            std::async(
                std::launch::async,
                [&files,
                 &enabled_rules,
                 &custom_rules,
                 &allowlist,
                 worker_start,
                 worker_end]() {

                    std::vector<
                        zerotrace::Finding
                    > worker_findings;

                    for (std::size_t i =
                             worker_start;
                         i < worker_end;
                         ++i) {

                        const std::string&
                            file =
                                files[i];

                        std::ifstream input(
                            file
                        );

                        if (!input.is_open()) {
                            continue;
                        }

                        std::string content(
                            (
                                std::istreambuf_iterator<char>(
                                    input
                                )
                            ),
                            std::istreambuf_iterator<char>()
                        );

                        std::vector<
                            zerotrace::Finding
                        > findings =
                            zerotrace::detect_secrets(
                                file,
                                content,
                                enabled_rules,
                                custom_rules
                            );

                        /*
                            Remove allowlisted
                            findings.
                        */

                        findings =
                            zerotrace::filter_allowlisted(
                                findings,
                                allowlist
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

    std::vector<zerotrace::Finding>
        all_findings;

    for (auto& task :
         tasks) {

        std::vector<
            zerotrace::Finding
        > findings =
            task.get();

        all_findings.insert(
            all_findings.end(),
            findings.begin(),
            findings.end()
        );
    }

    /*
        Stop the timer after scanning.
    */

    const auto scan_end =
        std::chrono::steady_clock::now();

    const std::chrono::duration<double>
        elapsed =
            scan_end -
            scan_start;

    const double
        scan_time_seconds =
            elapsed.count();

    /*
        Save baseline.
    */

    if (!save_baseline_path.empty()) {

        if (!zerotrace::save_baseline(
                save_baseline_path,
                all_findings
            )) {

            std::cerr
                << "Error: could not save baseline to "
                << save_baseline_path
                << "\n";

            return 2;
        }

        if (!json_output &&
            !sarif_output &&
            output_path.empty()) {

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

    std::unordered_set<std::string>
        baseline;

    if (!baseline_path.empty()) {

        baseline =
            zerotrace::load_baseline(
                baseline_path
            );

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

    for (const auto& finding :
         all_findings) {

        if (!baseline_path.empty()) {

            const std::string fingerprint =
                zerotrace::create_finding_fingerprint(
                    finding
                );

            if (baseline.find(
                    fingerprint
                ) == baseline.end()) {

                ++new_findings;
            }
        }
    }

    /*
        Build report.
    */

    std::string report;

    if (sarif_output) {

        report =
            zerotrace::build_sarif_report(
                all_findings
            );
    }

    else if (json_output) {

        report =
            build_json_report(
                all_findings,
                files.size(),
                thread_count,
                rules_path,
                baseline,
                baseline_path,
                new_findings,
                scan_time_seconds
            );
    }

    else {

        report =
            build_text_report(
                all_findings,
                path,
                files.size(),
                thread_count,
                baseline,
                baseline_path,
                new_findings,
                scan_time_seconds
            );
    }

    /*
        Write report to file.
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

        std::cout
            << report;
    }

    /*
        Exit codes:

        0 = no findings / no new findings
        1 = findings / new findings
        2 = scanner error
    */

    if (!baseline_path.empty()) {

        return new_findings > 0
            ? 1
            : 0;
    }

    return all_findings.empty()
        ? 0
        : 1;
}