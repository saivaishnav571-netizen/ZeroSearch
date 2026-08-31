#include "scanner.h"

#include <filesystem>
#include <fstream>
#include <string>
#include <unordered_set>
#include <vector>

namespace zerotrace {

bool should_scan_file(const std::string& path) {

    const std::filesystem::path file_path(path);

    const std::string filename =
        file_path.filename().string();

    const std::string extension =
        file_path.extension().string();

    if (filename == ".env" ||
        filename == "Dockerfile" ||
        filename == "Makefile") {

        return true;
    }

    const std::unordered_set<std::string> allowed_extensions = {
        ".c",
        ".cc",
        ".cpp",
        ".h",
        ".hh",
        ".hpp",
        ".py",
        ".js",
        ".ts",
        ".java",
        ".go",
        ".rs",
        ".php",
        ".rb",
        ".swift",
        ".kt",
        ".json",
        ".xml",
        ".yaml",
        ".yml",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
        ".txt"
    };

    return allowed_extensions.find(extension) !=
           allowed_extensions.end();
}

static std::vector<std::string> load_ignore_rules(
    const std::filesystem::path& root
) {

    std::vector<std::string> rules;

    const std::filesystem::path ignore_file =
        root / ".zerotraceignore";

    std::ifstream input(ignore_file);

    if (!input.is_open()) {
        return rules;
    }

    std::string line;

    while (std::getline(input, line)) {

        // Remove Windows carriage return.
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        // Ignore blank lines.
        if (line.empty()) {
            continue;
        }

        // Ignore comments.
        if (line[0] == '#') {
            continue;
        }

        // Remove trailing slash.
        if (line.back() == '/') {
            line.pop_back();
        }

        if (!line.empty()) {
            rules.push_back(line);
        }
    }

    return rules;
}

static bool wildcard_match(
    const std::string& text,
    const std::string& pattern
) {

    std::size_t text_index = 0;
    std::size_t pattern_index = 0;

    std::size_t star_index =
        std::string::npos;

    std::size_t match_index = 0;

    while (text_index < text.size()) {

        if (pattern_index < pattern.size() &&
            (pattern[pattern_index] == '?' ||
             pattern[pattern_index] == text[text_index])) {

            ++text_index;
            ++pattern_index;
        }

        else if (pattern_index < pattern.size() &&
                 pattern[pattern_index] == '*') {

            star_index = pattern_index;
            match_index = text_index;
            ++pattern_index;
        }

        else if (star_index != std::string::npos) {

            pattern_index = star_index + 1;
            ++match_index;
            text_index = match_index;
        }

        else {

            return false;
        }
    }

    while (pattern_index < pattern.size() &&
           pattern[pattern_index] == '*') {

        ++pattern_index;
    }

    return pattern_index == pattern.size();
}

static bool should_ignore(
    const std::filesystem::path& root,
    const std::filesystem::path& current,
    const std::vector<std::string>& rules
) {

    const std::filesystem::path relative =
        std::filesystem::relative(current, root);

    const std::string relative_path =
        relative.generic_string();

    const std::string filename =
        current.filename().string();

    for (const std::string& rule : rules) {

        // Exact relative path.
        if (relative_path == rule) {
            return true;
        }

        // Exact filename/directory name.
        if (filename == rule) {
            return true;
        }

        // Wildcard matching.
        if (wildcard_match(filename, rule)) {
            return true;
        }

        if (wildcard_match(relative_path, rule)) {
            return true;
        }
    }

    return false;
}

std::vector<std::string> scan_directory(
    const std::string& path
) {

    std::vector<std::string> files;

    const std::filesystem::path root(path);

    const std::vector<std::string> ignore_rules =
        load_ignore_rules(root);

    const std::unordered_set<std::string> built_in_ignored_directories = {
        ".git",
        ".vscode",
        "build",
        "node_modules"
    };

    std::filesystem::recursive_directory_iterator iterator(
        root
    );

    std::filesystem::recursive_directory_iterator end;

    while (iterator != end) {

        const auto& entry = *iterator;

        if (entry.is_directory()) {

            const std::string directory_name =
                entry.path().filename().string();

            // Existing built-in exclusions.
            if (built_in_ignored_directories.find(
                    directory_name
                ) != built_in_ignored_directories.end()) {

                iterator.disable_recursion_pending();

                ++iterator;
                continue;
            }

            // User-defined exclusions.
            if (should_ignore(
                    root,
                    entry.path(),
                    ignore_rules
                )) {

                iterator.disable_recursion_pending();

                ++iterator;
                continue;
            }
        }

        else if (entry.is_regular_file()) {

            if (should_ignore(
                    root,
                    entry.path(),
                    ignore_rules
                )) {

                ++iterator;
                continue;
            }

            if (should_scan_file(
                    entry.path().string()
                )) {

                files.push_back(
                    entry.path().string()
                );
            }
        }

        ++iterator;
    }

    return files;
}

}