#ifndef ZEROTRACE_HTML_REPORT_H
#define ZEROTRACE_HTML_REPORT_H

#include <string>
#include <vector>

#include "finding.h"

namespace zerotrace {

std::string build_html_report(
    const std::vector<Finding>& findings,
    std::size_t files_scanned,
    unsigned int thread_count,
    double scan_time_seconds
);

}

#endif