#include "allowlist.h"

#include <fstream>
#include <string>

namespace zerotrace {

static std::string normalize_path(
    std::string path
) {
    /*
        Convert Windows separators to
        forward slashes.
    */
    for (char& character : path) {

        if (character == '\\') {
            character = '/';
        }
    }

    /*
        Normalize paths such as:

        ./testdata/file.cpp

        into:

        testdata/file.cpp

        This allows the allowlist to match
        regardless of whether the user writes
        ./ at the beginning.
    */
    while (path.rfind("./", 0) == 0) {
        path.erase(0, 2);
    }

    return path;
}

static std::string trim(
    std::string value
) {
    const std::size_t first =
        value.find_first_not_of(" \t\r\n");

    if (first == std::string::npos) {
        return "";
    }

    const std::size_t last =
        value.find_last_not_of(" \t\r\n");

    return value.substr(
        first,
        last - first + 1
    );
}

static std::string make_finding_key(
    const std::string& file,
    int line,
    const std::string& type
) {
    return normalize_path(file) +
           "|" +
           std::to_string(line) +
           "|" +
           type;
}

Allowlist load_allowlist(
    const std::string& path
) {
    Allowlist allowlist;

    std::ifstream input(path);

    if (!input.is_open()) {
        return allowlist;
    }

    std::string line;

    while (std::getline(input, line)) {

        line = trim(line);

        if (line.empty()) {
            continue;
        }

        /*
            Ignore comments.
        */
        if (line.rfind("#", 0) == 0) {
            continue;
        }

        /*
            Rule-level allowlist:

            rule|Password
        */
        if (line.rfind("rule|", 0) == 0) {

            const std::string rule =
                trim(line.substr(5));

            if (!rule.empty()) {
                allowlist.rules.insert(rule);
            }

            continue;
        }

        /*
            File-level allowlist:

            file|testdata/example.cpp
        */
        if (line.rfind("file|", 0) == 0) {

            const std::string file =
                normalize_path(
                    trim(line.substr(5))
                );

            if (!file.empty()) {
                allowlist.files.insert(file);
            }

            continue;
        }

        /*
            Finding-level allowlist:

            finding|testdata/example.cpp|10|Password
        */
        if (line.rfind("finding|", 0) == 0) {

            const std::string data =
                line.substr(8);

            const std::size_t first_separator =
                data.find('|');

            if (first_separator ==
                std::string::npos) {

                continue;
            }

            const std::size_t second_separator =
                data.find(
                    '|',
                    first_separator + 1
                );

            if (second_separator ==
                std::string::npos) {

                continue;
            }

            const std::string file =
                normalize_path(
                    trim(
                        data.substr(
                            0,
                            first_separator
                        )
                    )
                );

            const std::string line_text =
                trim(
                    data.substr(
                        first_separator + 1,
                        second_separator -
                        first_separator - 1
                    )
                );

            const std::string type =
                trim(
                    data.substr(
                        second_separator + 1
                    )
                );

            try {

                const int line_number =
                    std::stoi(line_text);

                if (!file.empty() &&
                    !type.empty()) {

                    allowlist.findings.insert(
                        make_finding_key(
                            file,
                            line_number,
                            type
                        )
                    );
                }
            }
            catch (...) {

                /*
                    Ignore malformed
                    line numbers.
                */

                continue;
            }
        }
    }

    return allowlist;
}

bool is_allowlisted(
    const Finding& finding,
    const Allowlist& allowlist
) {

    /*
        1. Rule-level allowlist
    */

    if (allowlist.rules.find(
            finding.type
        ) != allowlist.rules.end()) {

        return true;
    }

    /*
        2. File-level allowlist
    */

    const std::string normalized_file =
        normalize_path(
            finding.file
        );

    if (allowlist.files.find(
            normalized_file
        ) != allowlist.files.end()) {

        return true;
    }

    /*
        3. Exact finding allowlist
    */

    const std::string finding_key =
        make_finding_key(
            finding.file,
            finding.line,
            finding.type
        );

    if (allowlist.findings.find(
            finding_key
        ) != allowlist.findings.end()) {

        return true;
    }

    return false;
}

std::vector<Finding> filter_allowlisted(
    const std::vector<Finding>& findings,
    const Allowlist& allowlist
) {

    std::vector<Finding> filtered;

    filtered.reserve(
        findings.size()
    );

    for (const Finding& finding :
         findings) {

        if (!is_allowlisted(
                finding,
                allowlist
            )) {

            filtered.push_back(
                finding
            );
        }
    }

    return filtered;
}

}