#include "sarif.h"

#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

namespace zerotrace {

static std::string escape_json(
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

static std::string normalize_path(
    std::string path
) {

    for (char& character : path) {

        if (character == '\\') {
            character = '/';
        }
    }

    return path;
}

static std::string severity_to_sarif_level(
    Severity severity
) {

    switch (severity) {

        case Severity::CRITICAL:
        case Severity::HIGH:
            return "error";

        case Severity::MEDIUM:
            return "warning";

        case Severity::LOW:
            return "note";
    }

    return "warning";
}

std::string build_sarif_report(
    const std::vector<Finding>& findings
) {

    std::ostringstream output;

    output << "{\n";

    output
        << "  \"version\": \"2.1.0\",\n";

    output
        << "  \"$schema\": "
           "\"https://json.schemastore.org/sarif-2.1.0.json\",\n";

    output
        << "  \"runs\": [\n";

    output
        << "    {\n";

    /*
        Tool information.
    */

    output
        << "      \"tool\": {\n";

    output
        << "        \"driver\": {\n";

    output
        << "          \"name\": \"ZeroTrace\",\n";

    /*
        This is the project's tool information URI.
    */

    output
        << "          \"informationUri\": "
           "\"https://github.com/zerotrace/zerotrace\",\n";

    /*
        Create one SARIF rule for each unique
        finding type.
    */

    output
        << "          \"rules\": [\n";

    std::vector<std::string> rule_names;

    for (const Finding& finding : findings) {

        bool exists = false;

        for (const std::string& name : rule_names) {

            if (name == finding.type) {

                exists = true;
                break;
            }
        }

        if (!exists) {
            rule_names.push_back(finding.type);
        }
    }

    for (std::size_t i = 0;
         i < rule_names.size();
         ++i) {

        output
            << "            {\n";

        output
            << "              \"id\": \""
            << escape_json(rule_names[i])
            << "\",\n";

        output
            << "              \"name\": \""
            << escape_json(rule_names[i])
            << "\"\n";

        output
            << "            }";

        if (i + 1 < rule_names.size()) {
            output << ",";
        }

        output << "\n";
    }

    output
        << "          ]\n";

    output
        << "        }\n";

    output
        << "      },\n";

    /*
        SARIF results.
    */

    output
        << "      \"results\": [\n";

    for (std::size_t i = 0;
         i < findings.size();
         ++i) {

        const Finding& finding =
            findings[i];

        const std::string normalized_path =
            normalize_path(finding.file);

        output
            << "        {\n";

        output
            << "          \"ruleId\": \""
            << escape_json(finding.type)
            << "\",\n";

        output
            << "          \"level\": \""
            << severity_to_sarif_level(
                   finding.severity)
            << "\",\n";

        output
            << "          \"message\": {\n";

        output
            << "            \"text\": \""
            << escape_json(
                   finding.type +
                   " detected by ZeroTrace")
            << "\"\n";

        output
            << "          },\n";

        /*
            Location of the finding.
        */

        output
            << "          \"locations\": [\n";

        output
            << "            {\n";

        output
            << "              \"physicalLocation\": {\n";

        output
            << "                \"artifactLocation\": {\n";

        output
            << "                  \"uri\": \""
            << escape_json(normalized_path)
            << "\"\n";

        output
            << "                },\n";

        output
            << "                \"region\": {\n";

        output
            << "                  \"startLine\": "
            << finding.line
            << "\n";

        output
            << "                }\n";

        output
            << "              }\n";

        output
            << "            }\n";

        output
            << "          ]\n";

        output
            << "        }";

        if (i + 1 < findings.size()) {
            output << ",";
        }

        output << "\n";
    }

    output
        << "      ]\n";

    output
        << "    }\n";

    output
        << "  ]\n";

    output
        << "}\n";

    return output.str();
}

}