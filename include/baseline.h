#ifndef ZEROTRACE_BASELINE_H
#define ZEROTRACE_BASELINE_H

#include <string>
#include <unordered_set>
#include <vector>

#include "finding.h"

namespace zerotrace {

std::string create_finding_fingerprint(
    const Finding& finding
);

bool save_baseline(
    const std::string& path,
    const std::vector<Finding>& findings
);

std::unordered_set<std::string> load_baseline(
    const std::string& path
);

}

#endif