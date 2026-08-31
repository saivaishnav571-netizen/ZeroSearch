#include "html_report.h"

#include <iomanip>
#include <map>
#include <sstream>
#include <string>

namespace zerotrace {

static std::string escape_html(
    const std::string& text
) {
    std::string result;

    for (char character : text) {

        switch (character) {

            case '&':
                result += "&amp;";
                break;

            case '<':
                result += "&lt;";
                break;

            case '>':
                result += "&gt;";
                break;

            case '"':
                result += "&quot;";
                break;

            case '\'':
                result += "&#39;";
                break;

            default:
                result += character;
        }
    }

    return result;
}

static std::string severity_to_string(
    Severity severity
) {
    switch (severity) {

        case Severity::LOW:
            return "LOW";

        case Severity::MEDIUM:
            return "MEDIUM";

        case Severity::HIGH:
            return "HIGH";

        case Severity::CRITICAL:
            return "CRITICAL";
    }

    return "UNKNOWN";
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

std::string build_html_report(
    const std::vector<Finding>& findings,
    std::size_t files_scanned,
    unsigned int thread_count,
    double scan_time_seconds
) {
    std::ostringstream output;

    int critical = 0;
    int high = 0;
    int medium = 0;
    int low = 0;

    std::map<std::string, int> rule_counts;

    for (const Finding& finding : findings) {

        rule_counts[finding.type]++;

        switch (finding.severity) {

            case Severity::CRITICAL:
                ++critical;
                break;

            case Severity::HIGH:
                ++high;
                break;

            case Severity::MEDIUM:
                ++medium;
                break;

            case Severity::LOW:
                ++low;
                break;
        }
    }

    output << R"HTML(
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>ZeroTrace Security Report</title>

<style>

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    padding: 0;
    font-family:
        Arial,
        Helvetica,
        sans-serif;
    background: #f4f6f8;
    color: #1f2937;
}

.container {
    max-width: 1400px;
    margin: 0 auto;
    padding: 30px;
}

.header {
    background: #111827;
    color: white;
    padding: 30px;
    border-radius: 12px;
    margin-bottom: 25px;
}

.header h1 {
    margin: 0 0 8px 0;
    font-size: 32px;
}

.header p {
    margin: 0;
    opacity: 0.75;
}

.stats {
    display: grid;
    grid-template-columns:
        repeat(auto-fit, minmax(180px, 1fr));
    gap: 15px;
    margin-bottom: 25px;
}

.stat {
    background: white;
    border-radius: 10px;
    padding: 20px;
    box-shadow:
        0 2px 8px rgba(0,0,0,0.06);
}

.stat-title {
    font-size: 13px;
    color: #6b7280;
    margin-bottom: 8px;
}

.stat-value {
    font-size: 28px;
    font-weight: bold;
}

.dashboard {
    display: grid;
    grid-template-columns:
        minmax(250px, 1fr)
        minmax(350px, 2fr);
    gap: 20px;
    margin-bottom: 25px;
}

.card {
    background: white;
    border-radius: 10px;
    padding: 22px;
    box-shadow:
        0 2px 8px rgba(0,0,0,0.06);
}

.card h2 {
    margin-top: 0;
}

.rule-row {
    display: flex;
    justify-content: space-between;
    padding: 8px 0;
    border-bottom:
        1px solid #e5e7eb;
}

.severity-row {
    display: flex;
    align-items: center;
    margin: 10px 0;
}

.severity-label {
    width: 90px;
    font-size: 13px;
    font-weight: bold;
}

.bar-container {
    flex: 1;
    height: 12px;
    background: #e5e7eb;
    border-radius: 8px;
    overflow: hidden;
}

.bar {
    height: 100%;
    border-radius: 8px;
}

.critical {
    background: #dc2626;
}

.high {
    background: #ea580c;
}

.medium {
    background: #ca8a04;
}

.low {
    background: #2563eb;
}

.severity-count {
    width: 40px;
    text-align: right;
    font-weight: bold;
}

.controls {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    margin-bottom: 15px;
}

.controls input,
.controls select {
    padding: 10px;
    border: 1px solid #d1d5db;
    border-radius: 6px;
    font-size: 14px;
}

.controls input {
    flex: 1;
    min-width: 250px;
}

.table-container {
    overflow-x: auto;
}

table {
    width: 100%;
    border-collapse: collapse;
}

th {
    background: #f9fafb;
    text-align: left;
    padding: 12px;
    font-size: 13px;
    border-bottom:
        2px solid #e5e7eb;
}

td {
    padding: 12px;
    border-bottom:
        1px solid #e5e7eb;
    font-size: 13px;
}

.badge {
    display: inline-block;
    padding: 4px 8px;
    border-radius: 5px;
    font-size: 11px;
    font-weight: bold;
    color: white;
}

.badge-critical {
    background: #dc2626;
}

.badge-high {
    background: #ea580c;
}

.badge-medium {
    background: #ca8a04;
}

.badge-low {
    background: #2563eb;
}

.secret {
    font-family: monospace;
}

.footer {
    margin-top: 25px;
    text-align: center;
    color: #6b7280;
    font-size: 13px;
}

@media (max-width: 800px) {

    .dashboard {
        grid-template-columns: 1fr;
    }

    .container {
        padding: 15px;
    }
}

</style>

</head>

<body>

<div class="container">

<div class="header">

<h1>ZeroTrace</h1>

<p>Secret Detection Security Report</p>

</div>

<div class="stats">

<div class="stat">
<div class="stat-title">Files Scanned</div>
<div class="stat-value">)HTML";

    output << files_scanned;

    output << R"HTML(</div>
</div>

<div class="stat">
<div class="stat-title">Total Findings</div>
<div class="stat-value">)HTML";

    output << findings.size();

    output << R"HTML(</div>
</div>

<div class="stat">
<div class="stat-title">Critical</div>
<div class="stat-value">)HTML";

    output << critical;

    output << R"HTML(</div>
</div>

<div class="stat">
<div class="stat-title">High</div>
<div class="stat-value">)HTML";

    output << high;

    output << R"HTML(</div>
</div>

<div class="stat">
<div class="stat-title">Scan Time</div>
<div class="stat-value">)HTML";

    output
        << std::fixed
        << std::setprecision(3)
        << scan_time_seconds
        << "s";

    output << R"HTML(</div>
</div>

<div class="stat">
<div class="stat-title">Threads</div>
<div class="stat-value">)HTML";

    output << thread_count;

    output << R"HTML(</div>
</div>

</div>

<div class="dashboard">

<div class="card">

<h2>Severity</h2>
)HTML";

    const int total =
        static_cast<int>(findings.size());

    auto percentage =
        [total](int value) -> int {

            if (total == 0) {
                return 0;
            }

            return
                (value * 100) / total;
        };

    output << R"HTML(

<div class="severity-row">

<div class="severity-label">
CRITICAL
</div>

<div class="bar-container">
<div class="bar critical"
     style="width:)HTML";

    output << percentage(critical);

    output << R"HTML(%"></div>
</div>

<div class="severity-count">
)HTML";

    output << critical;

    output << R"HTML(
</div>

</div>

<div class="severity-row">

<div class="severity-label">
HIGH
</div>

<div class="bar-container">
<div class="bar high"
     style="width:)HTML";

    output << percentage(high);

    output << R"HTML(%"></div>
</div>

<div class="severity-count">
)HTML";

    output << high;

    output << R"HTML(
</div>

</div>

<div class="severity-row">

<div class="severity-label">
MEDIUM
</div>

<div class="bar-container">
<div class="bar medium"
     style="width:)HTML";

    output << percentage(medium);

    output << R"HTML(%"></div>
</div>

<div class="severity-count">
)HTML";

    output << medium;

    output << R"HTML(
</div>

</div>

<div class="severity-row">

<div class="severity-label">
LOW
</div>

<div class="bar-container">
<div class="bar low"
     style="width:)HTML";

    output << percentage(low);

    output << R"HTML(%"></div>
</div>

<div class="severity-count">
)HTML";

    output << low;

    output << R"HTML(
</div>

</div>

</div>

<div class="card">

<h2>Findings by Rule</h2>
)HTML";

    if (rule_counts.empty()) {

        output
            << "<p>No findings detected.</p>\n";
    }

    else {

        for (const auto& entry :
             rule_counts) {

            output
                << "<div class=\"rule-row\">"
                << "<span>"
                << escape_html(entry.first)
                << "</span>"
                << "<strong>"
                << entry.second
                << "</strong>"
                << "</div>\n";
        }
    }

    output << R"HTML(

</div>

</div>

<div class="card">

<h2>Findings</h2>

<div class="controls">

<input
    type="text"
    id="search"
    placeholder="Search findings..."
    onkeyup="filterFindings()">

<select
    id="severityFilter"
    onchange="filterFindings()">

<option value="">All Severities</option>
<option value="CRITICAL">Critical</option>
<option value="HIGH">High</option>
<option value="MEDIUM">Medium</option>
<option value="LOW">Low</option>

</select>

<select
    id="ruleFilter"
    onchange="filterFindings()">

<option value="">All Rules</option>
)HTML";

    for (const auto& entry :
         rule_counts) {

        output
            << "<option value=\""
            << escape_html(entry.first)
            << "\">"
            << escape_html(entry.first)
            << "</option>\n";
    }

    output << R"HTML(

</select>

</div>

<div class="table-container">

<table id="findingsTable">

<thead>

<tr>

<th>Severity</th>
<th>Type</th>
<th>File</th>
<th>Line</th>
<th>Confidence</th>
<th>Entropy</th>
<th>Value</th>

</tr>

</thead>

<tbody>
)HTML";

    for (const Finding& finding :
         findings) {

        const std::string severity =
            severity_to_string(
                finding.severity
            );

        std::string badge_class =
            "badge-low";

        if (finding.severity ==
            Severity::CRITICAL) {

            badge_class =
                "badge-critical";
        }

        else if (finding.severity ==
                 Severity::HIGH) {

            badge_class =
                "badge-high";
        }

        else if (finding.severity ==
                 Severity::MEDIUM) {

            badge_class =
                "badge-medium";
        }

        output
            << "<tr>\n"

            << "<td>"
            << "<span class=\"badge "
            << badge_class
            << "\">"
            << severity
            << "</span>"
            << "</td>\n"

            << "<td>"
            << escape_html(finding.type)
            << "</td>\n"

            << "<td>"
            << escape_html(
                   normalize_path(
                       finding.file
                   )
               )
            << "</td>\n"

            << "<td>"
            << finding.line
            << "</td>\n"

            << "<td>"
            << finding.confidence
            << "%"
            << "</td>\n"

            << "<td>"
            << std::fixed
            << std::setprecision(2)
            << finding.entropy
            << "</td>\n"

            << "<td class=\"secret\">"
            << escape_html(
                   finding.matched_text
               )
            << "</td>\n"

            << "</tr>\n";
    }

    output << R"HTML(

</tbody>

</table>

</div>

</div>

<div class="footer">

Generated by ZeroTrace

</div>

</div>

<script>

function filterFindings() {

    const search =
        document
            .getElementById("search")
            .value
            .toLowerCase();

    const severity =
        document
            .getElementById("severityFilter")
            .value;

    const rule =
        document
            .getElementById("ruleFilter")
            .value;

    const rows =
        document
            .querySelectorAll(
                "#findingsTable tbody tr"
            );

    rows.forEach(function(row) {

        const text =
            row.textContent
                .toLowerCase();

        const rowSeverity =
            row.children[0]
                .textContent
                .trim();

        const rowRule =
            row.children[1]
                .textContent
                .trim();

        const matchesSearch =
            text.includes(search);

        const matchesSeverity =
            severity === "" ||
            rowSeverity === severity;

        const matchesRule =
            rule === "" ||
            rowRule === rule;

        row.style.display =
            matchesSearch &&
            matchesSeverity &&
            matchesRule
                ? ""
                : "none";
    });
}

</script>

</body>

</html>
)HTML";

    return output.str();
}

}