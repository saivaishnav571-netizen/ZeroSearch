#ifndef ZEROTRACE_ALLOWLIST_H
#define ZEROTRACE_ALLOWLIST_H

#include <string>
#include <unordered_set>
#include <vector>

#include "finding.h"

namespace zerotrace {

struct Allowlist {
    std::unordered_set<std::string> rules;
    std::unordered_set<std::string> files;
    std::unordered_set<std::string> findings;
};

Allowlist load_allowlist(
    const std::string& path
);

bool is_allowlisted(
    const Finding& finding,
    const Allowlist& allowlist
);

std::vector<Finding> filter_allowlisted(
    const std::vector<Finding>& findings,
    const Allowlist& allowlist
);

}

#endif